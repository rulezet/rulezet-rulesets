rule sig_20160315_2eb2e74fa4af663fd51009084582f245 {
  meta:
    description = "datamaliciousorder - file 20160315_2eb2e74fa4af663fd51009084582f245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6b67887e7fccdc4589946a08097683159d6aeb164b0d5ff610398ece24b395f"

  strings:
    $s1  = "return ANDMpEH[0] + ANDMpEH[2] + ANDMpEH[4] + \".F\" + ANDMpEH[7] + ANDMpEH[9] + ANDMpEH[12] + ANDMpEH[14];" fullword ascii
    $s2  = "var hI = true  , WzaD = DTB[7] + DTB[9] + DTB[11];" fullword ascii
    $s3  = "var ANDMpEH = FGMBh(\"Sc oIGTnXS r VTPjDzHpZ ipting AgspeBr vSG ile blrztLTLmZJRiJ System zW AdLNy Obj YEcfRe ect qeveZyc IfNcZ" ascii
    $s4  = "var DTB = (\"2.XMLHTTP SzWIvBW NzUWB XML ream St QFXmJXel AD cTGNPOF O qAQp D\").split(\" \");" fullword ascii
    $s5  = "ohIgy.open(vyUDZ,DmCmh,false);" fullword ascii
    $s6  = "var ANDMpEH = FGMBh(\"Sc oIGTnXS r VTPjDzHpZ ipting AgspeBr vSG ile blrztLTLmZJRiJ System zW AdLNy Obj YEcfRe ect qeveZyc IfNcZ" ascii
    $s7  = "return TXId.ExpandEnvironmentStrings(MOEJC);" fullword ascii
    $s8  = "GPv = Q; break; " fullword ascii
    $s9  = "function vIWV(vJOFc) {" fullword ascii
    $s10 = "return new ActiveXObject(tEiwlE);" fullword ascii
    $s11 = "function FLKn(atscI) {" fullword ascii
    $s12 = "function IZMTiyYD() {" fullword ascii
    $s13 = "return emOG.responseBody;" fullword ascii
    $s14 = "return RsBlIU.position=647-647;" fullword ascii
    $s15 = "function FGMBh(xFV,aprVF) {" fullword ascii
    $s16 = "function WnUAB(RsBlIU) {" fullword ascii
    $s17 = "function Mhpp(JiYaH,QzYhe) {" fullword ascii
    $s18 = "function TqdEFCPf(Rvs) {" fullword ascii
    $s19 = "function GoFvb(tEiwlE) {" fullword ascii
    $s20 = "if(Q>=r.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}