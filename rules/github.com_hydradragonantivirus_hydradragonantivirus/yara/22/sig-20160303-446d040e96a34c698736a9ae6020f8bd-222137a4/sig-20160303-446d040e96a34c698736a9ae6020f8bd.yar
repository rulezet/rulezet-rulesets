rule sig_20160303_446d040e96a34c698736a9ae6020f8bd {
  meta:
    description = "datamaliciousorder - file 20160303_446d040e96a34c698736a9ae6020f8bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dbe801587dba8a0d23e60b77f338aea54ae087a07ac611d9913c5e29f846367"

  strings:
    $s1  = "var DmQrs = \"iVMXHI BRb pt.Shell tZlHHVG Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var mFE = (fLL + \"TTP\" + \" OIpLsHp PbbUG XML ream St mUzyhZrJ AD RilnPob OD\").split(\" \");" fullword ascii
    $s3  = "var Dc = true  , XFWP = mFE[7] + \"\" + mFE[9];" fullword ascii
    $s4  = "return dcXtqLM[0] + dcXtqLM[2] + dcXtqLM[4] + \".F\" + dcXtqLM[7] + dcXtqLM[9] + dcXtqLM[12] + dcXtqLM[14];" fullword ascii
    $s5  = "IvucP.open(QuGXC,pqPGu,false);" fullword ascii
    $s6  = "var dcXtqLM = \"Sc CWQiizM r RKlmpwLFP ipting HtCktGt URC ile DZGyYdgQoFVkYz System CQ sUXaQ Obj Okobns ect DihgXUb\".split(\" " ascii
    $s7  = "function NphBiKRzc(lmNGJ,eaSTy,iWPiZ) {" fullword ascii
    $s8  = "function xJIe(ovYsI,YZdcd) {" fullword ascii
    $s9  = "function XROobQBcm(IcxnznTZGyu) {" fullword ascii
    $s10 = "function hioZucSR() {" fullword ascii
    $s11 = "choKY += FnzVB.substr(S, 416-415);" fullword ascii
    $s12 = "function HUxavYI(SRyE) {" fullword ascii
    $s13 = "function Wtfa(IvucP,pqPGu,QuGXC) {" fullword ascii
    $s14 = "function RtLH(SqYzq) {" fullword ascii
    $s15 = "return GnRil.status;" fullword ascii
    $s16 = "if(N>=k.length) {break;}" fullword ascii
    $s17 = "function xOdS(FnzVB) {" fullword ascii
    $s18 = "fVk = N; break; " fullword ascii
    $s19 = "return OVtitfY" fullword ascii
    $s20 = "return choKY;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}