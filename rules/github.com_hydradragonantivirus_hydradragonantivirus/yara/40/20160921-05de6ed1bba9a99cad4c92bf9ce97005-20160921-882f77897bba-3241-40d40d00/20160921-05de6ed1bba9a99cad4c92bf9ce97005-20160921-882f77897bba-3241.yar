rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_882f77897bba_3241 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = "rn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s2 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s3 = " f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s4 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s5 = "{return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})()" ascii
    $s6 = "urn \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}