rule sig_20151209_abd77ffd8c6ad6a15fc886b45e8225ca {
  meta:
    description = "datamaliciousorder - file 20151209_abd77ffd8c6ad6a15fc886b45e8225ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d6c59da637fd3af5fde59a9262201bb140b726f676e4f6efa57a4e843c43b30"

  strings:
    $s1  = "function dAvJz(WxxTgpHIWNV,feqNXIAIkbloU,cwpKmIMo){mTds=parseInt(WxxTgpHIWNV,feqNXIAIkbloU);ELXcQ=mTds.toString(cwpKmIMo);return" ascii
    $s2  = "tjqJncF[ZTUvUqibmnf]=(-448+448)/61; while(true) { if(IPtjqJncF[ZTUvUqibmnf] > FbkEa[ZTUvUqibmnf].length-(246+241)/487) { break; " ascii
    $s3  = "function rWCsZqqogDzygiZQRDdQMNAZjgsVdeByRZZKvFVYLuwWMyxStpnPBc(QzbumGODlDhXO,BHHXMhEZdqlAUV){ return WTLfm[dAvJz(QzbumGODlDhXO[" ascii
    $s4  = "function IqlHXWOUVGrMrhQmu(FbkEa){NdFgilbizXt= '';for(ZTUvUqibmnf=(-263+263)/44; ZTUvUqibmnf < (934+284)/609; ZTUvUqibmnf++) {IP" ascii
    $s5  = "}} return NdFgilbizXt}" fullword ascii
    $s6  = "function IqlHXWOUVGrMrhQmu(FbkEa){NdFgilbizXt= '';for(ZTUvUqibmnf=(-263+263)/44; ZTUvUqibmnf < (934+284)/609; ZTUvUqibmnf++) {IP" ascii
    $s7  = "function rWCsZqqogDzygiZQRDdQMNAZjgsVdeByRZZKvFVYLuwWMyxStpnPBc(QzbumGODlDhXO,BHHXMhEZdqlAUV){ return WTLfm[dAvJz(QzbumGODlDhXO[" ascii
    $s8  = "function gxLMnuCfCyx(KYxhxBhD,lGvzNg){return KYxhxBhD.split(lGvzNg)}" fullword ascii
    $s9  = "function dAvJz(WxxTgpHIWNV,feqNXIAIkbloU,cwpKmIMo){mTds=parseInt(WxxTgpHIWNV,feqNXIAIkbloU);ELXcQ=mTds.toString(cwpKmIMo);return" ascii
    $s10 = " ELXcQ;}function CdSfEODzGKXtiUB(eXkzaNTazyZBYMlWE){eval(eXkzaNTazyZBYMlWE)}" fullword ascii
    $s11 = "function bXglfyK(wMjwpzJstbjVYuRGkhrQcAWXXrqSptzpepYE) {return !isNaN(parseFloat(wMjwpzJstbjVYuRGkhrQcAWXXrqSptzpepYE)) && isFin" ascii
    $s12 = "function bXglfyK(wMjwpzJstbjVYuRGkhrQcAWXXrqSptzpepYE) {return !isNaN(parseFloat(wMjwpzJstbjVYuRGkhrQcAWXXrqSptzpepYE)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}