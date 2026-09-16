rule sig_20160313_fdb8072f7c1040c9199e5b88e4088c75 {
  meta:
    description = "datamaliciousorder - file 20160313_fdb8072f7c1040c9199e5b88e4088c75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f40ca7de8026fb3a5c9e7115b585ee5be4e4993b68b7d2aa9733634829e23534"

  strings:
    $s1  = "var YL = true  , BZKW = PYw[7] + PYw[9] + PYw[11];" fullword ascii
    $s2  = "return MVEVzVp[0] + MVEVzVp[2] + MVEVzVp[4] + \".F\" + MVEVzVp[7] + MVEVzVp[9] + MVEVzVp[12] + MVEVzVp[14];" fullword ascii
    $s3  = "var PYw = (\"2.XMLHTTP YFKTenI iCmzI XML ream St fuXLABPR AD UwrGVTh O nulJ D\").split(\" \");" fullword ascii
    $s4  = "orxTe.open(gNHjb,ymHqc,false);" fullword ascii
    $s5  = "var MVEVzVp = \"Sc SofaXsm r AIFebxmIS ipting hvFCZNS gUp ile JeVXWUlzDnqwIC System cR IOrpl Obj NDYnub ect vMeEBNc\".split(\" " ascii
    $s6  = "return IjOVXCP" fullword ascii
    $s7  = "return snn.size;" fullword ascii
    $s8  = "function WRdH(orxTe,ymHqc,gNHjb) {" fullword ascii
    $s9  = "return Oevdr.status;" fullword ascii
    $s10 = "if (YoqSg > 194781-950){return true;} else {return false;}" fullword ascii
    $s11 = "function jBbg(OSiuM) {" fullword ascii
    $s12 = "hVe = F; break; " fullword ascii
    $s13 = "return rbRw.responseBody;" fullword ascii
    $s14 = "if (xcDKV == 357-157){return true;} else {return false;}" fullword ascii
    $s15 = "function XZjUP(TgbEBj) {" fullword ascii
    $s16 = "return lcFHEGh(wj,efEfm[155-149]+efEfm[511-504]+efEfm[514-506]);" fullword ascii
    $s17 = "function ReWXD(TydQcO) {" fullword ascii
    $s18 = "function soNb(xcDKV) {" fullword ascii
    $s19 = "function UoCfbaJT() {" fullword ascii
    $s20 = "return zxydB;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}