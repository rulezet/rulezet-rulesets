rule sig_20160301_b9a834ef3f75bfbf438a9a3bfa8c6774 {
  meta:
    description = "datamaliciousorder - file 20160301_b9a834ef3f75bfbf438a9a3bfa8c6774.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "486844a04b9c56d0cead2ad0c814eb35e31deb2bb3434e0b5bb9f789bdfd17b3"

  strings:
    $s1  = "var rC = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(MXmoP);" fullword ascii
    $s3  = "var pAb = (ECE + \"TTP\" + \" skvpmGy vnJVg XML ream St SjyIInaV AD XlLokYK OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + WLAKFue + \".F\" + XfjuExyefs + rdHGX + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var wx = true  , iGqW = pAb[7] + \"\" + pAb[9];" fullword ascii
    $s6  = "LvUjF.open(nQLmF,lMSLp,false);" fullword ascii
    $s7  = "function XVFobVNr() {" fullword ascii
    $s8  = "function IkfW(beYma) {" fullword ascii
    $s9  = "function uJzO(YUjZS) {" fullword ascii
    $s10 = "function Mjwf(RJCPD,baxYy) {" fullword ascii
    $s11 = "function bLOA(zZDQd) {" fullword ascii
    $s12 = "return Gd.ExpandEnvironmentStrings(rC);" fullword ascii
    $s13 = "DiV = J; break; " fullword ascii
    $s14 = "function vmAmLciJq(VQfwT,ZKUvM,YltKq) {" fullword ascii
    $s15 = "function IqHb(BDIRm,MWamz) {" fullword ascii
    $s16 = "function imnqTipIV(fjSUMqOLGfB) {" fullword ascii
    $s17 = "return kgEZH;" fullword ascii
    $s18 = "function KPXVX(KAExdS) {" fullword ascii
    $s19 = "function wQOE(tZPii) {" fullword ascii
    $s20 = "if(J>=x.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}