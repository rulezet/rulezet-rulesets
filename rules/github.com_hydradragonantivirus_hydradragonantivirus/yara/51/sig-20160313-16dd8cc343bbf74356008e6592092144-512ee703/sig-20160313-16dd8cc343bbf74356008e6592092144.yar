rule sig_20160313_16dd8cc343bbf74356008e6592092144 {
  meta:
    description = "datamaliciousorder - file 20160313_16dd8cc343bbf74356008e6592092144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4707d0cf07e6ff261145d351e0a571e5db710ec465440d251d04e359a06771d6"

  strings:
    $s1  = "return UFWwxCB[0] + UFWwxCB[2] + UFWwxCB[4] + \".F\" + UFWwxCB[7] + UFWwxCB[9] + UFWwxCB[12] + UFWwxCB[14];" fullword ascii
    $s2  = "var Nu = true  , WUid = TqG[7] + TqG[9] + TqG[11];" fullword ascii
    $s3  = "nDkOR.open(dZccf,jqKCj,false);" fullword ascii
    $s4  = "var UFWwxCB = \"Sc EGjvOBi r DgKpYUHoR ipting OKzPldX YKq ile ajVCWeHmoxdtnc System ji PxuFT Obj yKZBeD ect pbVahec\".split(\" " ascii
    $s5  = "var TqG = (\"2.XMLHTTP jEQROlX gvfOM XML ream St ssCSivZy AD APKIdjI O gAeJ D\").split(\" \");" fullword ascii
    $s6  = "function cPnG(AJJGW) {" fullword ascii
    $s7  = "if(K>=D.length) {break;}" fullword ascii
    $s8  = "function UYPW(USUWg) {" fullword ascii
    $s9  = "return agm.size;" fullword ascii
    $s10 = "if (wnQUz == 1069-869){return true;} else {return false;}" fullword ascii
    $s11 = "function AcBAIge(wedV,WgtCD) {" fullword ascii
    $s12 = "function ZHCSyKfd(agm) {" fullword ascii
    $s13 = "function UgRVW(chdRfz) {" fullword ascii
    $s14 = "function AyUAVXOWF(uyRHWrDsXCd) {" fullword ascii
    $s15 = "function IkJDUKe(ojfF) {" fullword ascii
    $s16 = "return YxSax.status;" fullword ascii
    $s17 = "return XhfArq.position=911-911;" fullword ascii
    $s18 = "return new ActiveXObject(chdRfz);" fullword ascii
    $s19 = "if (Xeimz > 186016-741){return true;} else {return false;}" fullword ascii
    $s20 = "function uaIf(ynYOI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}