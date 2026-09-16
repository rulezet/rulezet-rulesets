rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_e985c90f8141_1870 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1  = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s2  = "ction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return" ascii
    $s3  = "(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";}" ascii
    $s4  = "eturn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(" ascii
    $s5  = "ction f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s6  = "{return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(" ascii
    $s7  = "unction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){retu" ascii
    $s8  = "turn \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})()," ascii
    $s9  = "{return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";}" ascii
    $s10 = "){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}