rule _20160921_74a9afe189b59f0b8148a7f92f42b125_20160921_e6977bb87c75_3912 {
  meta:
    description = "datamaliciousorder - from files 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "ck(){return \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We" ascii
    $s2 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retu" ascii
    $s3 = "(){return \"Jo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";" ascii
    $s4 = "function fuck(){return \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s5 = "k(){return \"CCb\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\"" ascii
    $s6 = "n \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}