rule sig_20160314_4b4543966d70fd3990f3e1b460021fb7 {
  meta:
    description = "datamaliciousorder - file 20160314_4b4543966d70fd3990f3e1b460021fb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0122f2f168dd702693c7deb2e170ba76ed7ca3b278c6b150a6522e46d85079cb"

  strings:
    $s1  = "var YD = true  , ctKI = cjy[7] + cjy[9] + cjy[11];" fullword ascii
    $s2  = "return pwMkMGp[0] + pwMkMGp[2] + pwMkMGp[4] + \".F\" + pwMkMGp[7] + pwMkMGp[9] + pwMkMGp[12] + pwMkMGp[14];" fullword ascii
    $s3  = "tdtUM.open(aNaCe,vdMms,false);" fullword ascii
    $s4  = "var pwMkMGp = \"Sc PVNupNF r vFRdlScRV ipting nJTQdGX KIo ile SMkJxOAXmHEOdf System Ch dqZTn Obj WVhamv ect JAlIRWX Nadkj\".spli" ascii
    $s5  = "var pwMkMGp = \"Sc PVNupNF r vFRdlScRV ipting nJTQdGX KIo ile SMkJxOAXmHEOdf System Ch dqZTn Obj WVhamv ect JAlIRWX Nadkj\".spli" ascii
    $s6  = "var cjy = (\"2.XMLHTTP rOSfrHB IGfEK XML ream St uKRQvKSM AD AsJCuWn O ttmR D\").split(\" \");" fullword ascii
    $s7  = "return xtmkA;" fullword ascii
    $s8  = "QMD = y; break; " fullword ascii
    $s9  = "if (F >= jceVz.length) {break;}" fullword ascii
    $s10 = "function uiRq(lrrsy,AcFVn) {" fullword ascii
    $s11 = "function BbBv(NEkuA) {" fullword ascii
    $s12 = "return KSr.size;" fullword ascii
    $s13 = "return VPfDI.status;" fullword ascii
    $s14 = "function LGexX(AGCiQn) {" fullword ascii
    $s15 = "return ILMxye.position=148-148;" fullword ascii
    $s16 = "return RFGK.responseBody;" fullword ascii
    $s17 = "function iYAX(StGGB) {" fullword ascii
    $s18 = "return Wmzhamy" fullword ascii
    $s19 = "function QABmmbW(cKFo,MCqAy) {" fullword ascii
    $s20 = "function uWKawaTR(KSr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}