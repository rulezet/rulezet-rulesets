rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_37277908f811_3601 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash3       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash4       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash5       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1 = "n \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";" ascii
    $s3 = "(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s4 = "(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){r" ascii
    $s5 = "\"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s6 = "00(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}