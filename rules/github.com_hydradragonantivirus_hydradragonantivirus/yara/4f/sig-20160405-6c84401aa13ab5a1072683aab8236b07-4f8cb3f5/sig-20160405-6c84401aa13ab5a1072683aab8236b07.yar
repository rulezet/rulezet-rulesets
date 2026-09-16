rule sig_20160405_6c84401aa13ab5a1072683aab8236b07 {
  meta:
    description = "datamaliciousorder - file 20160405_6c84401aa13ab5a1072683aab8236b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf90542332cafcea8a308ccb3f4350111a98ea08fd47e3027fd268c1d22772c"

  strings:
    $s1  = "return AOcBOWH[0] + AOcBOWH[2] + AOcBOWH[4] + \".F\" + AOcBOWH[7] + AOcBOWH[9] + AOcBOWH[12] + AOcBOWH[14];" fullword ascii
    $s2  = "var ij = true  , QXqT = YlV[7] + YlV[9] + YlV[11];" fullword ascii
    $s3  = "gdfd.open(IvPFd,EIiqM,false);" fullword ascii
    $s4  = "var YlV = (\"2.XMLHTTP emnhkbM TqkwZ XML ream St kDkucpIq AD wsCnkRo O EiXx D\").split(\" \");" fullword ascii
    $s5  = "function iRqD(ATebo) {" fullword ascii
    $s6  = "return uyhowPb;" fullword ascii
    $s7  = "return yLEEM.status;" fullword ascii
    $s8  = "if (npCLZ > 178616-469){return true;} else {return false;}" fullword ascii
    $s9  = "function hVHy(npCLZ) {" fullword ascii
    $s10 = "function AFhVIbkg(vAH) {" fullword ascii
    $s11 = "return pSa.split(qhbMx);" fullword ascii
    $s12 = "return QdNvD;" fullword ascii
    $s13 = "function JVGR(eInTp,EIiqM,IvPFd) {" fullword ascii
    $s14 = "function nihKm(pSa,qhbMx) {" fullword ascii
    $s15 = "return \"polkOooVlWmicK\";" fullword ascii
    $s16 = "return xKWgYmk[0];" fullword ascii
    $s17 = "function eAnECyd(gbKk) {" fullword ascii
    $s18 = "function utnGDHrbE(YdiXMfMzEbE) {" fullword ascii
    $s19 = "if (vxnBg == 1117-917){return true;} else {return false;}" fullword ascii
    $s20 = "function PIlu(ZunKk,fSLIX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}