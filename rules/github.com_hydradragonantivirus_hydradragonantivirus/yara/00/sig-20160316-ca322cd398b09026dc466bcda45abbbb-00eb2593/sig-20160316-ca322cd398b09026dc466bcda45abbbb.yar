rule sig_20160316_ca322cd398b09026dc466bcda45abbbb {
  meta:
    description = "datamaliciousorder - file 20160316_ca322cd398b09026dc466bcda45abbbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c49b6394d5ff483f056cf774889959e724ef44864ad56bbd5f302731f093574f"

  strings:
    $s1 = "while (RVzUEkUlvTleB[WASNBudXdaRJ + CCaL + ShJdxmKesswGSoF + xEx + NHmCkryzxiOey] < 4 ) {WScript[LyLlMquKI + tPyTGmwXPwJ + yvoTD" ascii
    $s2 = "while (RVzUEkUlvTleB[WASNBudXdaRJ + CCaL + ShJdxmKesswGSoF + xEx + NHmCkryzxiOey] < 4 ) {WScript[LyLlMquKI + tPyTGmwXPwJ + yvoTD" ascii
    $s3 = "RVzUEkUlvTleB[zpW + XVz + wjtWZYJS](pUCYaCxqdOvKpy, zKqxIvqjdZZNg + BDEakOr + sTFwr + VQgnsdrrT + aBQekLLnK + MPWuBBXwHkbQg + JQ" ascii
    $s4 = "function xJdsjRkgCQxL(n){return dNHhES + iZpZNID + MIEhAsGJN + fZYDeAGz + yyrmuyWroxAqFd + lIBuXkOsutj;}" fullword ascii
    $s5 = "xmVYrGfcRzm + GJGEOSztSYloW + neXkFvGTSFnxj + gnKnKbRkqX + dLgDJOeUdp, false);" fullword ascii
    $s6 = "function mXLJivm(pTYfreGLtU){cQfobjfOCtxG[BwrsogquPOBBMT + yTugkjRewsL](pTYfreGLtU, 0, 0);}" fullword ascii
    $s7 = "var NYWtipt = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}