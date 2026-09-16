rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_6d18600f3019_4243 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1 = "00(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";}" ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s3 = "nction f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s4 = "on f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"K" ascii
    $s5 = "eturn \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}