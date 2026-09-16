rule sig_20160321_93ee25bd05c5d96800915508fd8cd10a {
  meta:
    description = "datamaliciousorder - file 20160321_93ee25bd05c5d96800915508fd8cd10a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acb4d164e65e0e9febfd92d64c2c1835368ba5b2b58979422341e143a2a7f003"

  strings:
    $s1  = "return WScript.CreateObject(Nskbj);" fullword ascii
    $s2  = "var FJ = true  , Pvbr = ymr[7] + ymr[9] + ymr[11];" fullword ascii
    $s3  = "return WYPaePU[0] + WYPaePU[2] + WYPaePU[4] + \".F\" + WYPaePU[7] + WYPaePU[9] + WYPaePU[12] + WYPaePU[14];" fullword ascii
    $s4  = "var WYPaePU = UlMmL(hRRZIRmbIw+\" \"+\"System dw bxEwe Obj jxZCnX ect ZpkBskH Xirtq\", \" \");" fullword ascii
    $s5  = "var ymr = (\"2.XMLHTTP WzuronO QJgbd XML ream St cDOGHlgJ AD xHDBmzI O Enje D\").split(\" \");" fullword ascii
    $s6  = "SpoSE.open(iXhNE,gJhRx,false);" fullword ascii
    $s7  = "function uAoi(yDkVA,sCmKe) {" fullword ascii
    $s8  = "function aPQvB(DMLYYi) {" fullword ascii
    $s9  = "function KZKf(TAGUA) {" fullword ascii
    $s10 = "function TuyU(zvtmZ) {" fullword ascii
    $s11 = "if (U >= zvtmZ.length) {break;}" fullword ascii
    $s12 = "function etZG(piEzX) {" fullword ascii
    $s13 = "return axTb.ExpandEnvironmentStrings(PWqNj);" fullword ascii
    $s14 = "function jLmKBSKv(dKS) {" fullword ascii
    $s15 = "return oIyBh;" fullword ascii
    $s16 = "return jlrNUML(qe,hsUKu[328-322]+hsUKu[901-894]+hsUKu[982-974]);" fullword ascii
    $s17 = "function UlMmL(vXR,rgwyU) {" fullword ascii
    $s18 = "function DYRJ(cVinB) {" fullword ascii
    $s19 = "var ZXaJxpoe = UlMmL(\"SemE@Ws@HdzTjkc@c@mDSUCh@ri\"+\"@pt@LrAoFTjE@.S@KnYHJ@he@KYoWQt@ll@qErzVpc@YBObkBaQ@cuIs\", \"@\");" fullword ascii
    $s20 = "function kurn(DMLGM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}