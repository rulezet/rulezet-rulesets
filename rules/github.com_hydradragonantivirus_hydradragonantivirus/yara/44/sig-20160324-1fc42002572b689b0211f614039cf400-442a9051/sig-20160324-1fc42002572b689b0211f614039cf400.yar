rule sig_20160324_1fc42002572b689b0211f614039cf400 {
  meta:
    description = "datamaliciousorder - file 20160324_1fc42002572b689b0211f614039cf400.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1161c94c94d2cdff3ef25a69d0eb2df2a1b961f17617faac26baff7f57d726c8"

  strings:
    $s1  = "return WScript.CreateObject(JnRWt);" fullword ascii
    $s2  = "var gu = true  , hxGc = QcD[7] + QcD[9] + QcD[11];" fullword ascii
    $s3  = "return hYYiuov[0] + hYYiuov[2] + hYYiuov[4] + \".F\" + hYYiuov[7] + hYYiuov[9] + hYYiuov[12] + hYYiuov[14];" fullword ascii
    $s4  = "var QcD = (\"2.XMLHTTP VLLiSmq dFhpt XML ream St wWecevcK AD qUdJxIP O DHtA D\").split(\" \");" fullword ascii
    $s5  = "ZBQt.open(JEWxA,GFauc,false);" fullword ascii
    $s6  = "if(c>=O.length) {break;}" fullword ascii
    $s7  = "function qzZI(drubQ,GFauc,JEWxA) {" fullword ascii
    $s8  = "function HeOlU(MpHrAm) {" fullword ascii
    $s9  = "return vsLRq.status;" fullword ascii
    $s10 = "return FNH.size;" fullword ascii
    $s11 = "return yBk.split(VnhfN);" fullword ascii
    $s12 = "if (ijBDD == 490-290){return true;} else {return false;}" fullword ascii
    $s13 = "return NisYOz/*XGot0ArkDlpKeDjfSfhu0DQgj*/.position=216-216;" fullword ascii
    $s14 = "return new ActiveXObject(DQOY);" fullword ascii
    $s15 = "function QOLj(ijBDD) {" fullword ascii
    $s16 = "return EnfvX;" fullword ascii
    $s17 = "function Biyx(LlSYK) {" fullword ascii
    $s18 = "function XRRNqigUy(XfMlafEgbOF) {" fullword ascii
    $s19 = "var xpSWMUu = \"JYByTe*grm*pt.S\"+\"hell*gKIuPKr*Scri*\";" fullword ascii
    $s20 = "function tinRpQFzR(jlzfF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}