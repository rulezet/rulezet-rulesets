rule sig_20160307_14763f88557a4082a2124a152d86996a {
  meta:
    description = "datamaliciousorder - file 20160307_14763f88557a4082a2124a152d86996a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b9cb6951a3831feb79f631cdacb3a8f7fe3993dc68a583a4de13fe41320eb6a"

  strings:
    $s1  = "function GeTYfGg(gezA) {" fullword ascii
    $s2  = "return fyicgjn[0] + fyicgjn[2] + fyicgjn[4] + \".F\" + fyicgjn[7] + fyicgjn[9] + fyicgjn[12] + fyicgjn[14];" fullword ascii
    $s3  = "var db = true  , JHbC = mCj[7] + mCj[9] + mCj[11];" fullword ascii
    $s4  = "var fyicgjn = \"Sc lHAIIvT r aUzVSDUJQ ipting LYqVgWe Bbj ile fytjppSiKlEFeJ System St HtgUH Obj nfXeHA ect ErYmHjV\".split(\" " ascii
    $s5  = "xKLnU.open(cpAtC,URQaF,false);" fullword ascii
    $s6  = "var mCj = (\"2.XMLHTTP RLRYfDR RLURi XML ream St MKXYHMLI AD FvKQPwz O KtBW D\").split(\" \");" fullword ascii
    $s7  = "function JAwp(xocyT,wFyrr) {" fullword ascii
    $s8  = "return gezA.responseBody;" fullword ascii
    $s9  = "function rAhRdJGbe(GDuLCpPAZiL) {" fullword ascii
    $s10 = "return nGfCr.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s11 = "if (((new Date())>0,7562717888)) {" fullword ascii
    $s12 = "return MP.ExpandEnvironmentStrings(BKVqP[6]+BKVqP[7]+BKVqP[8]);" fullword ascii
    $s13 = "function fYLk(XsQgw) {" fullword ascii
    $s14 = "function nRtVrTU(xLPa) {" fullword ascii
    $s15 = "return XMM.size;" fullword ascii
    $s16 = "if (a >= DYheF.length) {break;}" fullword ascii
    $s17 = "function wNnbY(GllROu) {" fullword ascii
    $s18 = "function yEFf(HtgKb) {" fullword ascii
    $s19 = "function PBRp(GrlSy) {" fullword ascii
    $s20 = "function yzid(RgfTa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}