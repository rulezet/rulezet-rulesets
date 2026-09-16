rule sig_20160308_4c45ea6f9784a969e20af60381d715f8 {
  meta:
    description = "datamaliciousorder - file 20160308_4c45ea6f9784a969e20af60381d715f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bce1296c4539ca373f6fd7b508f0a46bb01e9c6e0a6dd88baad210c82223f1d"

  strings:
    $s1  = "var GykOKHU = \"Sc wotVeWI r ejrzbiNGv ipting wgRRfSB yYk ile XfGbXyyEFXazPE System ve TIDDD Obj Dcksmn ect PxeELvw\".split(\" " ascii
    $s2  = "return GykOKHU[0] + GykOKHU[2] + GykOKHU[4] + \".F\" + GykOKHU[7] + GykOKHU[9] + GykOKHU[12] + GykOKHU[14];" fullword ascii
    $s3  = "var vd = true  , QDkz = iAX[7] + iAX[9] + iAX[11];" fullword ascii
    $s4  = "var iAX = (\"2.XMLHTTP PtrFpnh aKMWS XML ream St JDJaRnCq AD ShTuMrp O JxzN D\").split(\" \");" fullword ascii
    $s5  = "uaYIt.open(vEHpR,Xssxi,false);" fullword ascii
    $s6  = "return zubkx;" fullword ascii
    $s7  = "function fZaQSbna(yXs) {" fullword ascii
    $s8  = "return new ActiveXObject(eXPKGA);" fullword ascii
    $s9  = "function sHmJvlLgS(AvjRx,IJCZO,hhqJB,SEGt) {" fullword ascii
    $s10 = "if (PqkBp == 460-260){return true;} else {return false;}" fullword ascii
    $s11 = "return yXs.size;" fullword ascii
    $s12 = "juF = o; break; " fullword ascii
    $s13 = "function iOGY(PqkBp) {" fullword ascii
    $s14 = "function TriU(fKAbb,SRcVi) {" fullword ascii
    $s15 = "function ygJeyFy(lXiB) {" fullword ascii
    $s16 = "function bVBEgGzXG(CfqMFeDzKKt) {" fullword ascii
    $s17 = "function FFlX(zKCnm) {" fullword ascii
    $s18 = "function XzuULXCk() {" fullword ascii
    $s19 = "function gQot(aeqsh,kQlZN) {" fullword ascii
    $s20 = "return aZ.ExpandEnvironmentStrings(MmppQ[6]+MmppQ[7]+MmppQ[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}