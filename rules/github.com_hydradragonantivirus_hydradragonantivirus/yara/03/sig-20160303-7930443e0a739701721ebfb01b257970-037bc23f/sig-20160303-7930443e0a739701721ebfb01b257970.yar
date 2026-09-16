rule sig_20160303_7930443e0a739701721ebfb01b257970 {
  meta:
    description = "datamaliciousorder - file 20160303_7930443e0a739701721ebfb01b257970.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cd22a0518e2e851bb46a8e10a4cb0d176552aa829119e3354b56e4388c79e4c"

  strings:
    $s1  = "var UDLuz = \"IBLweu pMH pt.Shell CGzOcZh Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var nhW = (xYa + \"TTP\" + \" nebRxqn XseBH XML ream St CQuQBvBa AD WiaPSvm OD\").split(\" \");" fullword ascii
    $s3  = "var oi = true  , fahI = nhW[7] + \"\" + nhW[9];" fullword ascii
    $s4  = "return yvWRJji[0] + yvWRJji[2] + yvWRJji[4] + \".F\" + yvWRJji[7] + yvWRJji[9] + yvWRJji[12] + yvWRJji[14];" fullword ascii
    $s5  = "var yvWRJji = \"Sc LWWlEga r RzTGwqViF ipting qExJOSb pqD ile rKkBIpKbOFwdjW System wl Qaunn Obj YSugOW ect tPIwsjv\".split(\" " ascii
    $s6  = "cJrHr.open(LvPgM,xbRAH,false);" fullword ascii
    $s7  = "function eQRZ(WFAWa,ojiVF) {" fullword ascii
    $s8  = "function abFq(jwcLO) {" fullword ascii
    $s9  = "function rAlMz(XYDREH) {" fullword ascii
    $s10 = "function pNCp(crIuI) {" fullword ascii
    $s11 = "if (oOPBx > 176811-516){return true;} else {return false;}" fullword ascii
    $s12 = "function hMWB(lWxyz) {" fullword ascii
    $s13 = "function PDNECUTee(GyTGHAvdUSF) {" fullword ascii
    $s14 = "function PlhVwGD(yaJp) {" fullword ascii
    $s15 = "function Zppe(cJrHr,xbRAH,LvPgM) {" fullword ascii
    $s16 = "return lWxyz.status;" fullword ascii
    $s17 = "function MDsY(oOPBx) {" fullword ascii
    $s18 = "fvw = a; break; " fullword ascii
    $s19 = "return HYMH.responseBody;" fullword ascii
    $s20 = "function AWZR(DUTSp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}