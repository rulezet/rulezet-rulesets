rule sig_20160411_a49b43ebd3e117843d8aad5fc6a223b9 {
  meta:
    description = "datamaliciousorder - file 20160411_a49b43ebd3e117843d8aad5fc6a223b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae031e5b88acd7efe23a27e4c9d0bc6d1a69366ffdffc62660fb36d6e25a95bb"

  strings:
    $s1  = "var ya = true  , adBh = pwa[7] + pwa[9] + pwa[11];" fullword ascii
    $s2  = "return oXWhpjT[0] + oXWhpjT[2] + oXWhpjT[4] + \".F\" + oXWhpjT[7] + oXWhpjT[9] + oXWhpjT[12] + oXWhpjT[14];" fullword ascii
    $s3  = "lOOi.open(Jhmsy,KlwzB,false);" fullword ascii
    $s4  = "var pwa = (\"2.XMLHTTP XtgOWiP iTMJn XML ream St MIlMUszh AD EyoVTHc O zDEP D\").split(\" \");" fullword ascii
    $s5  = "if(n>=g.length) {break;}" fullword ascii
    $s6  = "function lbTz(NvZnm,KlwzB,Jhmsy) {" fullword ascii
    $s7  = "return DkWPk;" fullword ascii
    $s8  = "function AYID(CmaFW) {" fullword ascii
    $s9  = "var THey = mmc+bCYmWI[0]+bCYmWI[1];" fullword ascii
    $s10 = "function DUWrc(uOp,sbSZT) {" fullword ascii
    $s11 = "return JMYtqtc(bu,MEnJJr+uiEix[935-927]);" fullword ascii
    $s12 = "if (lfvgw > 170412-725){return true;} else {return false;}" fullword ascii
    $s13 = "if (V >= cuBxD.length) {break;}" fullword ascii
    $s14 = "function MYHk(vhcPE) {" fullword ascii
    $s15 = "function UTXZDN(KfpPTdq) {" fullword ascii
    $s16 = "function qwQh(lfvgw) {" fullword ascii
    $s17 = "function JMYtqtc(toLk,ZobLV) {" fullword ascii
    $s18 = "OKe = n; break; " fullword ascii
    $s19 = "function zkuvldOnx(PHRxy) {" fullword ascii
    $s20 = "return \"oarkndhGUHeagY\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}