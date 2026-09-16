rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_382a0f9b1ae6_1832 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash5       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1  = "unction f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s2  = "return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tb\";})(),(" ascii
    $s3  = "f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn" ascii
    $s4  = "(function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s5  = "unction f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){ret" ascii
    $s6  = " f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QD" ascii
    $s7  = "(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\"" ascii
    $s8  = "000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv" ascii
    $s9  = "function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){ret" ascii
    $s10 = "Gn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}