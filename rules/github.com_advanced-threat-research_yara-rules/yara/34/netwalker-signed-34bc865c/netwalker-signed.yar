import "pe"
rule netwalker_signed {
    
   meta:
   
        description = "Rule to detect Netwalker ransomware digitally signed."
        author = "Marc Rivero | McAfee ATR Team"
        reference = "https://www.ccn-cert.cni.es/comunicacion-eventos/comunicados-ccn-cert/9802-publicado-un-informe-de-codigo-danino-sobre-netwalker.html"
        date = "2020-03-30"
        note = "The rule will hit also some Dridex samples digitally signed"
        
    condition:
    
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/CN=EWBTCAXQKUMDTHCXCZ"  and
         pe.signatures[i].serial == "17:16:bb:93:fb:a9:a2:41:ba:a8:2e:c7:5e:ff:0c" or
         pe.signatures[i].thumbprint == "a4:28:e9:4a:61:3a:1f:cf:ff:08:bf:e7:61:51:64:31:1a:6f:87:bc")
}