rule sig_20160517_a61ea76e929e82f4d1a6647b60a31218 {
  meta:
    description = "datamaliciousorder - file 20160517_a61ea76e929e82f4d1a6647b60a31218.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a12f39d4939d64ae3de3451d79979c7a9c5f4f6f978d0dd2ee0ad28d3c5db601"

  strings:
    $s1 = "var w2akl='vnqif3akfmhsrinltx ogxylql2hwbewffzgods2e3sduipbpr2tpvyszcnyqeaz42frmgllcjhesq=rvksl\\'lwnjmtm4mpqcwgukknop1cbigwmuof" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}