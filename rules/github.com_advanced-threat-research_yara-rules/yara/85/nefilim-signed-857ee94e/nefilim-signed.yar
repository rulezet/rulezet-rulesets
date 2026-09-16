import "pe"
rule nefilim_signed {

    meta:

        description = "Rule to detect Nefilim samples digitally signed"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-02"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Nefilim"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
        hash = "353ee5805bc5c7a98fb5d522b15743055484dc47144535628d102a4098532cd5"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Red GmbH/CN=Red GmbH"  and
         pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
         pe.signatures[i].thumbprint == "5b:19:58:8b:78:74:0a:4c:5d:08:41:99:dc:0f:52:a6:1f:38:00:99")
}