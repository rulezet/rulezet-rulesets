rule sig_20160315_2f075fa2666d5eebb9a18adb2c5a39db {
  meta:
    description = "datamaliciousorder - file 20160315_2f075fa2666d5eebb9a18adb2c5a39db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ba7d1daaded91f5218f5c8fbd572f66f0d7d3a1a80d5b47152bdad9a8241093"

  strings:
    $s1 = "function HOEc(gWx){WshShell[xcDtwzq + AAtefd](gWx, 0, 0);}" fullword ascii
    $s2 = "while (Rjc.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "Rjc[vKgjdGKEEZcKx + ShKcpEYXo + pjtojREUR](xOfLZNquu + ahkQ, mYfOluZYsk + xmtDprZXA + uGy + bAKyBSsLB + MZxUBmhBySmwy + BBehL + " ascii
    $s4 = "function ixHiIQLlOkdCus(n){return kaeQD + cTyQ + cDOG + YujZlhsalhTfZk + BfuKpbRW + fmaIHmNbhCUGlV + KYYmLrYbNPQyT + nWUP;}" fullword ascii
    $s5 = "hSAESf + rmE + EjNkKbhbtiPiYm + kuu0 + TekP + qxhpyrWJv + byYZsTb + oLnsK + yWyqwLfc + AllCBFpwFgL + qbIRHIJEW, false);" fullword ascii
    $s6 = "var wvw = new Date();" fullword ascii
    $s7 = "var deED = \"hg\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}