rule sig_20160312_6a6aff230516f6f98f5a6504c9c1ba09 {
  meta:
    description = "datamaliciousorder - file 20160312_6a6aff230516f6f98f5a6504c9c1ba09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e040fcb08737910bf98ab68d06ecff20f48ad3b01b6baaf8dc3a351f4fcba5ea"

  strings:
    $s1  = "return bqLAgBF[0] + bqLAgBF[2] + bqLAgBF[4] + \".F\" + bqLAgBF[7] + bqLAgBF[9] + bqLAgBF[12] + bqLAgBF[14];" fullword ascii
    $s2  = "var zf = true  , aOro = zuM[7] + zuM[9] + zuM[11];" fullword ascii
    $s3  = "function gtmp(WEyuk) {" fullword ascii
    $s4  = "oSeVd.open(XhFkR,PgRiB,false);" fullword ascii
    $s5  = "var zuM = (\"2.XMLHTTP VHqDOAf AnvMI XML ream St MVEUaoaA AD KpFOTAj O iJTn D\").split(\" \");" fullword ascii
    $s6  = "var bqLAgBF = \"Sc ejcdtYf r RUPdXCPpu ipting DlCJLBb hAj ile SreBGQhiJfcDSd System Sg bBDQR Obj zOQiuH ect zloUJRe\".split(\" " ascii
    $s7  = "function iInO(ZzNpk) {" fullword ascii
    $s8  = "function gTjGs(KrehUO) {" fullword ascii
    $s9  = "return QmoyVms(LN,ViIXL[622-616]+ViIXL[605-598]+ViIXL[866-858]);" fullword ascii
    $s10 = "return AGgOD;" fullword ascii
    $s11 = "return tWCS.ExpandEnvironmentStrings(PZkgj);" fullword ascii
    $s12 = "hPe = O; break; " fullword ascii
    $s13 = "return CdUUTds" fullword ascii
    $s14 = "function GgvEl(QeLPeP) {" fullword ascii
    $s15 = "function jhFC(RbNGm) {" fullword ascii
    $s16 = "function QmoyVms(tWCS,PZkgj) {" fullword ascii
    $s17 = "return Qqz.size;" fullword ascii
    $s18 = "function KlSc(NseRV) {" fullword ascii
    $s19 = "if(O>=w.length) {break;}" fullword ascii
    $s20 = "if (I >= WEyuk.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}