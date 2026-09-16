rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_9dad243650b7_4640 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_9dad243650b7872772e7037b467b5a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"

  strings:
    $s1 = "urn \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s2 = "0(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\"" ascii
    $s3 = "{return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()" ascii
    $s5 = "f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}