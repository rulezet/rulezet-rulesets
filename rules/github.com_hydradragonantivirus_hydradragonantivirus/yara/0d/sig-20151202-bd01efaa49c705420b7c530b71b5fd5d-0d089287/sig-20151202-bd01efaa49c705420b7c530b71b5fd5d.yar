rule sig_20151202_bd01efaa49c705420b7c530b71b5fd5d {
  meta:
    description = "datamaliciousorder - file 20151202_bd01efaa49c705420b7c530b71b5fd5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "312b3d5e220ea5d27761eca7af4d321f540c7484adff38886d03277688e8cb66"

  strings:
    $s1 = "romCharCode(lqeGzsKyNdseYUweGNoHFzSp[IIDWkF]);}BcGQEVNULmTQooroLam+=String.fromCharCode(lqeGzsKyNdseYUweGNoHFzSp[3]);return BcGQ" ascii
    $s2 = "function rDPmRNaFaSpgXQiYcqRPDyXhkm(sqKsGOJEtWxwxxvmnChuqRQxoMoH){eval(sqKsGOJEtWxwxxvmnChuqRQxoMoH)};" fullword ascii
    $s3 = "function C(lqeGzsKyNdseYUweGNoHFzSp){ BcGQEVNULmTQooroLam='';for(IIDWkF = 0; IIDWkF < 3; IIDWkF++){BcGQEVNULmTQooroLam+=String.f" ascii
    $s4 = "function C(lqeGzsKyNdseYUweGNoHFzSp){ BcGQEVNULmTQooroLam='';for(IIDWkF = 0; IIDWkF < 3; IIDWkF++){BcGQEVNULmTQooroLam+=String.f" ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}