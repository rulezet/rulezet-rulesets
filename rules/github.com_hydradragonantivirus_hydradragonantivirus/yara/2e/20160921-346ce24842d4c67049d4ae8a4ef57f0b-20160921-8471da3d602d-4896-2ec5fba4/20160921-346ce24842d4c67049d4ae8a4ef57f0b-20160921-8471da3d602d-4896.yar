rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_8471da3d602d_4896 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = ")(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000()" ascii
    $s2 = " \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s3 = "00(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj" ascii
    $s4 = "(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s5 = "eturn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}