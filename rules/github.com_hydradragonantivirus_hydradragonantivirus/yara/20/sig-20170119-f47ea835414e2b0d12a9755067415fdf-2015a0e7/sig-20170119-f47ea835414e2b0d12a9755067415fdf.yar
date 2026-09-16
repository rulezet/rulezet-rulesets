rule sig_20170119_f47ea835414e2b0d12a9755067415fdf {
  meta:
    description = "datamaliciousorder - file 20170119_f47ea835414e2b0d12a9755067415fdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34641ab2d5a5d84bcdbe1c8d6c87effc2a2a154627f81fdc0c8702d4363e37d2"

  strings:
    $s1 = "var pnicopbytci5 = new Function(ymuzdoskadjeruxbuvafofireqehbezihsejhynyvybfewimtuvcamsacajcoxwursagxilegzytiwoxabuxovewgyqbevmu" ascii
    $s2 = "var pnicopbytci5 = new Function(ymuzdoskadjeruxbuvafofireqehbezihsejhynyvybfewimtuvcamsacajcoxwursagxilegzytiwoxabuxovewgyqbevmu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}