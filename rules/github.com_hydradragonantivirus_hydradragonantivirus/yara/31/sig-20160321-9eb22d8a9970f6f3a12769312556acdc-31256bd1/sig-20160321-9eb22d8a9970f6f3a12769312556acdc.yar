rule sig_20160321_9eb22d8a9970f6f3a12769312556acdc {
  meta:
    description = "datamaliciousorder - file 20160321_9eb22d8a9970f6f3a12769312556acdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a21f72ab55e47e42292cd73cba2084c31c572cf64daa7616594d3d5c69bc76a"

  strings:
    $s1  = "return WScript.CreateObject(KVPqD);" fullword ascii
    $s2  = "var jW = true  , vNnY = Jrp[7] + Jrp[9] + Jrp[11];" fullword ascii
    $s3  = "return ENdZXpW[0] + ENdZXpW[2] + ENdZXpW[4] + \".F\" + ENdZXpW[7] + ENdZXpW[9] + ENdZXpW[12] + ENdZXpW[14];" fullword ascii
    $s4  = "var Jrp = (\"2.XMLHTTP akyDUMe JyzHj XML ream St eLNewtpE AD TdzcUeV O Vhmy D\").split(\" \");" fullword ascii
    $s5  = "POVIw.open(KnhKc,qWTxS,false);" fullword ascii
    $s6  = "var ENdZXpW = GrAeH(yFsTZotcVF+\" \"+\"System Ew chodV Obj RZxOLk ect eCtduCf RKwQS\", \" \");" fullword ascii
    $s7  = "function scePY(onhdMo) {" fullword ascii
    $s8  = "function qtcmlEh(zfEJ) {" fullword ascii
    $s9  = "return KeL.split(XKXJp);" fullword ascii
    $s10 = "function fuxw(fyLdb) {" fullword ascii
    $s11 = "return new ActiveXObject(GEXvNL);" fullword ascii
    $s12 = "return HWjP.ExpandEnvironmentStrings(XGkvw);" fullword ascii
    $s13 = "function jlGV(hUvFX) {" fullword ascii
    $s14 = "function BFjw(POVIw,qWTxS,KnhKc) {" fullword ascii
    $s15 = "function atzg(MHtmG,ArXLF) {" fullword ascii
    $s16 = "function qSAI(uOdDq) {" fullword ascii
    $s17 = "function GrAeH(KeL,XKXJp) {" fullword ascii
    $s18 = "function pwbxmixm(lWnY) {" fullword ascii
    $s19 = "function RYnjPgX(HWjP,XGkvw) {" fullword ascii
    $s20 = "function aEJf(yFEcj,wEoUX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}