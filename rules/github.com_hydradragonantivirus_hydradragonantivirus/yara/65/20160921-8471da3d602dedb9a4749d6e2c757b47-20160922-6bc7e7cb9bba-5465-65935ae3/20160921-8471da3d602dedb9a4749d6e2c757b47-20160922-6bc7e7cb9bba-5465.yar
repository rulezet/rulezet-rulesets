rule _20160921_8471da3d602dedb9a4749d6e2c757b47_20160922_6bc7e7cb9bba_5465 {
  meta:
    description = "datamaliciousorder - from files 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash2       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZFe\";})(),(function f000" ascii
    $s2 = " \"IAa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s3 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"UEg" ascii
    $s4 = "f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tn" ascii
    $s5 = "on f000(){return \"Sv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}