rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_dd666c66b3f1_4244 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";" ascii
    $s2 = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s3 = "urn \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4 = "){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(" ascii
    $s5 = "s\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}