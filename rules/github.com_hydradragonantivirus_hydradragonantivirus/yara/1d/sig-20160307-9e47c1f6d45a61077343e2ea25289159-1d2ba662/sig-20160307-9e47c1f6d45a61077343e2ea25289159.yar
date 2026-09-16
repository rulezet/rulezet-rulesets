rule sig_20160307_9e47c1f6d45a61077343e2ea25289159 {
  meta:
    description = "datamaliciousorder - file 20160307_9e47c1f6d45a61077343e2ea25289159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d30dea79db87e6baf8775b9f6dd896919316b0078547a055b5cd275309c78961"

  strings:
    $s1  = "return cuRsSWg[0] + cuRsSWg[2] + cuRsSWg[4] + \".F\" + cuRsSWg[7] + cuRsSWg[9] + cuRsSWg[12] + cuRsSWg[14];" fullword ascii
    $s2  = "var pQ = true  , PRwQ = GZa[7] + GZa[9] + GZa[11];" fullword ascii
    $s3  = "cjwqC.open(SOIWl,AwBoo,false);" fullword ascii
    $s4  = "var GZa = (\"2.XMLHTTP lYmCTZj UzitI XML ream St KBzaItZb AD oEQAUJV O GBGy D\").split(\" \");" fullword ascii
    $s5  = "var cuRsSWg = \"Sc UxkbBIf r JzaBuPxVM ipting FAmqZVg GSU ile kXlIEqBDaXsWHc System pH qpqlO Obj lpmXqi ect pVBgWtO\".split(\" " ascii
    $s6  = "if(s>=T.length) {break;}" fullword ascii
    $s7  = "function bgkJaBEzw(BafvI,KRuYW,dFelP,ueuB) {" fullword ascii
    $s8  = "function bUtLYgWf(hSx) {" fullword ascii
    $s9  = "if (h >= BbSsO.length) {break;}" fullword ascii
    $s10 = "return NuzvD.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s11 = "if (LZZJv > 193946-592){return true;} else {return false;}" fullword ascii
    $s12 = "return hSx.size;" fullword ascii
    $s13 = "function enyX(TDLhb,MKKeh) {" fullword ascii
    $s14 = "function QLlE(SuafA) {" fullword ascii
    $s15 = "inA = s; break; " fullword ascii
    $s16 = "function Lbcc(BbSsO) {" fullword ascii
    $s17 = "if (vjovy == 650-450){return true;} else {return false;}" fullword ascii
    $s18 = "function LwpfLLFA() {" fullword ascii
    $s19 = "function LFry(alFNI) {" fullword ascii
    $s20 = "return ik.ExpandEnvironmentStrings(XfMBu[6]+XfMBu[7]+XfMBu[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}