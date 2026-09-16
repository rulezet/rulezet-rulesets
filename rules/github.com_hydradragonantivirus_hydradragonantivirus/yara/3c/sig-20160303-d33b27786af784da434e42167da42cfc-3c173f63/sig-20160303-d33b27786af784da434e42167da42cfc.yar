rule sig_20160303_d33b27786af784da434e42167da42cfc {
  meta:
    description = "datamaliciousorder - file 20160303_d33b27786af784da434e42167da42cfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51dc973b30edddb6a1c8a9640ed4c3a979f4dd726efa0e2f91f14faf9e2f6c8d"

  strings:
    $s1  = "var KZjJU = \"NhjAEL jRI pt.Shell IPzvrPs Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var BMn = (AFX + \"TTP\" + \" FgMnwxg vYLEU XML ream St LdUECrVG AD LIYZryP OD\").split(\" \");" fullword ascii
    $s3  = "return XmxkweA[0] + XmxkweA[2] + XmxkweA[4] + \".F\" + XmxkweA[7] + XmxkweA[9] + XmxkweA[12] + XmxkweA[14];" fullword ascii
    $s4  = "var wh = true  , LgAY = BMn[7] + \"\" + BMn[9];" fullword ascii
    $s5  = "ZEffG.open(pKVKy,SlSkS,false);" fullword ascii
    $s6  = "var XmxkweA = \"Sc zbmYGRU r veZrYBoiH ipting xFibDNG EKT ile KRYhNsufpYMSGh System iS yWXtc Obj qekABb ect cBWzTKq\".split(\" " ascii
    $s7  = "return yT.ExpandEnvironmentStrings(KZjJU[6]);" fullword ascii
    $s8  = "function nnKi(pfgdD) {" fullword ascii
    $s9  = "function XAij(HDrDx,hvfgq) {" fullword ascii
    $s10 = "function vSUI(sgkmM,LKDfd) {" fullword ascii
    $s11 = "function qtmT(zeNyT) {" fullword ascii
    $s12 = "function jnyTRVODt(lOsWQ,jKXmd,HWdjm) {" fullword ascii
    $s13 = "qHx = J; break; " fullword ascii
    $s14 = "return SIfgJ.status;" fullword ascii
    $s15 = "function zaef(wzciV) {" fullword ascii
    $s16 = "function ptcvCXh(vAHQ) {" fullword ascii
    $s17 = "if (oylWS == 968-768){return true;} else {return false;}" fullword ascii
    $s18 = "function lDUb(bdMWx) {" fullword ascii
    $s19 = "if (zeNyT > 182990-104){return true;} else {return false;}" fullword ascii
    $s20 = "return new ActiveXObject(YURKUY);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}