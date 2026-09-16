rule sig_20160516_91165f888bdb9a4a8c2d9d10ce7d7a3f {
  meta:
    description = "datamaliciousorder - file 20160516_91165f888bdb9a4a8c2d9d10ce7d7a3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3521ab97875300baa50a44fddf37f39be944655eccca0f6a116db2c2a78669"

  strings:
    $s1 = "var ov3='vigxbeadbix3rv3dqc kjcayobjxlrixnvugfaartgpp4li1tim3vccqqqmvzzxemjeko2visysn4lfq4ojm=i24rx\\'k2n2ntzplqccgqu1lnuidumigs" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}