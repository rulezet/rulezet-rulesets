rule sig_20160316_8b86a3d0a30ab2dbe96bcdf4a7c5a3e2 {
  meta:
    description = "datamaliciousorder - file 20160316_8b86a3d0a30ab2dbe96bcdf4a7c5a3e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c39b9a0aadc5820504b2849c877cf42258777d8614f694ec21f00695ca31b2"

  strings:
    $s1 = "while (uaBSzSGHAWHPSD[eQmtHh + dfcmFeYkKRkVf + noxunjMTTIfwCes + AXAhjDE + YAOL] < 4 ) {WScript[tyBjVZDOxdgmBo + sQEbhB](1000)};" ascii
    $s2 = "uaBSzSGHAWHPSD[eLtGj + vrFFQyCM](hOcB + NRlNpAqVE, CihvLyrg + KroueyrArFjkHdi + tRUnFrV + SogJeHL + VjsPC + VKQliWUOzJyXlTM + dV" ascii
    $s3 = "function vhDkIzCTvp(IAasTZa){wuEeDfFdGSnTwvR[HZiNWj + GUhslfI](IAasTZa, 0, 0);}" fullword ascii
    $s4 = "function yfnDADwiftJ(n){return AUaecZLm + YBXboqIWeUTjAXj + pfGdSooqyaqIuIY + dqJEPgY + mlcHNJfSLcR + iLYEnLqbIeaskd + OQFsOWwet" ascii
    $s5 = "XWtVHDdcdI + nWXtePTmcyUgWR + ZmzGiiDMOcJun + EQunLyZZzQImAXn + cmNmxVpvxLznIzO + TrsX + mCunykfich + OdQEH, false);" fullword ascii
    $s6 = "function yfnDADwiftJ(n){return AUaecZLm + YBXboqIWeUTjAXj + pfGdSooqyaqIuIY + dqJEPgY + mlcHNJfSLcR + iLYEnLqbIeaskd + OQFsOWwet" ascii
    $s7 = "var uwvE = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}