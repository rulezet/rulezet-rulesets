rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_32423c6c4f53_4566 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash4       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash5       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";" ascii
    $s2 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn" ascii
    $s3 = "n\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s4 = "eturn \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})()," ascii
    $s5 = "n f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}