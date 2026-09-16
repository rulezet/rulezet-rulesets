rule sig_20160311_9f65eebe306d85267eb26a128fee7680 {
  meta:
    description = "datamaliciousorder - file 20160311_9f65eebe306d85267eb26a128fee7680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4de2d50262922eb8f468851b8755ed2e9114c42cb7635d3a21071fedb17a33c9"

  strings:
    $s1  = "var mn = true  , EpNX = tvV[7] + tvV[9] + tvV[11];" fullword ascii
    $s2  = "return VeAwPYZ[0] + VeAwPYZ[2] + VeAwPYZ[4] + \".F\" + VeAwPYZ[7] + VeAwPYZ[9] + VeAwPYZ[12] + VeAwPYZ[14];" fullword ascii
    $s3  = "var tvV = (\"2.XMLHTTP wQeihzA YnWes XML ream St vNibyKaG AD eIBMBfA O tLgn D\").split(\" \");" fullword ascii
    $s4  = "var VeAwPYZ = \"Sc HqXPHCm r lLsrwhkBk ipting iYPbrFj UiJ ile dMRYGXaDIwDCKU System fJ WHprM Obj NTWnVi ect mWtcIsa\".split(\" " ascii
    $s5  = "pYiOm.open(opWnb,NhHuG,false);" fullword ascii
    $s6  = "function qFklD(enffhC) {" fullword ascii
    $s7  = "function aQNqMOn(hZio) {" fullword ascii
    $s8  = "return BPPzzbE" fullword ascii
    $s9  = "return jyXk.ExpandEnvironmentStrings(HokxT);" fullword ascii
    $s10 = "function mmJP(urebp) {" fullword ascii
    $s11 = "function wfcvnwqFc(ViWfslUvEAi) {" fullword ascii
    $s12 = "if (Z >= CQKBD.length) {break;}" fullword ascii
    $s13 = "function iUAB(CQKBD) {" fullword ascii
    $s14 = "if (TIDtQ > 140194-458){return true;} else {return false;}" fullword ascii
    $s15 = "return IRdol;" fullword ascii
    $s16 = "function TXNUvfFL() {" fullword ascii
    $s17 = "return PYUDLRM(vL,EKjXx[506-500]+EKjXx[694-687]+EKjXx[983-975]);" fullword ascii
    $s18 = "return ckW.size;" fullword ascii
    $s19 = "return hZio.responseBody;" fullword ascii
    $s20 = "function guqyDZZl(ckW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}