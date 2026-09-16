rule sig_20160311_5c6c3f46fd75faaf6dd9fec5f20a2ce2 {
  meta:
    description = "datamaliciousorder - file 20160311_5c6c3f46fd75faaf6dd9fec5f20a2ce2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a943eb7465e64e92ec0eb1c65e7f625c4a0b79f4e211317c3514ebe80265dc7c"

  strings:
    $s1  = "var Qv = true  , onLj = DUi[7] + DUi[9] + DUi[11];" fullword ascii
    $s2  = "return uagOLRQ[0] + uagOLRQ[2] + uagOLRQ[4] + \".F\" + uagOLRQ[7] + uagOLRQ[9] + uagOLRQ[12] + uagOLRQ[14];" fullword ascii
    $s3  = "var DUi = (\"2.XMLHTTP KYMpKRj YlLbG XML ream St OobklGCf AD tplkbMk O jhuw D\").split(\" \");" fullword ascii
    $s4  = "KPddv.open(hFawZ,xwHSX,false);" fullword ascii
    $s5  = "var uagOLRQ = \"Sc JtQNjDS r FrCcGShuD ipting TdMEosR tSC ile BBJbmuBUlsoLCW System CL FGCJN Obj RYVZfo ect XEoghgK\".split(\" " ascii
    $s6  = "return RCzqSZl(XQ,IUKMR[596-590]+IUKMR[399-392]+IUKMR[869-861]);" fullword ascii
    $s7  = "function RCzqSZl(voUn,hgqGA) {" fullword ascii
    $s8  = "function DMnth(ygfyqL) {" fullword ascii
    $s9  = "function ZotciWes(vdg) {" fullword ascii
    $s10 = "return BjoIF.status;" fullword ascii
    $s11 = "function GiUYN(llQFfM) {" fullword ascii
    $s12 = "return AVmaY;" fullword ascii
    $s13 = "return voUn.ExpandEnvironmentStrings(hgqGA);" fullword ascii
    $s14 = "return XrHByhX" fullword ascii
    $s15 = "YiN = j; break; " fullword ascii
    $s16 = "function zdRjbWnIq() {" fullword ascii
    $s17 = "function WAxx(WsPhB) {" fullword ascii
    $s18 = "function PzWamNW(Hanw) {" fullword ascii
    $s19 = "function rIDPUTGu() {" fullword ascii
    $s20 = "function QCPftHon(yBtOw,rbrhsZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}