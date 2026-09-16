rule sig_20160323_f125753b115a748e5f3e92330c32354d {
  meta:
    description = "datamaliciousorder - file 20160323_f125753b115a748e5f3e92330c32354d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "600b2937994e49bffab00e72a60364a5f1ed8b114fabfd471dd490886753ecca"

  strings:
    $s1  = "return WScript.CreateObject(NuMGD);" fullword ascii
    $s2  = "return rDZWBZR[0] + rDZWBZR[2] + rDZWBZR[4] + \".F\" + rDZWBZR[7] + rDZWBZR[9] + rDZWBZR[12] + rDZWBZR[14];" fullword ascii
    $s3  = "var xq = true  , TGhA = WBY[7] + WBY[9] + WBY[11];" fullword ascii
    $s4  = "function IupU(pPKEY) {" fullword ascii
    $s5  = "var WBY = (\"2.XMLHTTP FoEgiAu zUmnw XML ream St BaOaJjJX AD SBtJHqC O TdHz D\").split(\" \");" fullword ascii
    $s6  = "ThGV.open(MSAOr,FEojF,false);" fullword ascii
    $s7  = "var rDZWBZR = PmqdV(cogfQmamWh+\" \"+\"System Vw jhHwy Obj ioGUSq ect ehbwaBP AmntG\", \" \");" fullword ascii
    $s8  = "function XwPYbQm(VJAu) {" fullword ascii
    $s9  = "return pteIA.status;" fullword ascii
    $s10 = "function zyCIKOFw(TPbr) {" fullword ascii
    $s11 = "return kZW.split(ajoXv);" fullword ascii
    $s12 = "function zEYznqxqN(vNzGVvMjJQI) {" fullword ascii
    $s13 = "PTS = U; break; " fullword ascii
    $s14 = "return TpPUy;" fullword ascii
    $s15 = "return Ozs.size;" fullword ascii
    $s16 = "function TWeRc(aOXfGz) {" fullword ascii
    $s17 = "return yWDRzB/*2ajog2jpBQTPfGtUfY4Qx5WCJ*/.position=296-296;" fullword ascii
    $s18 = "function Vain(mtGFZ) {" fullword ascii
    $s19 = "function SdEY(rgEMc) {" fullword ascii
    $s20 = "var ug = Vain(ti).split(\" \");" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}