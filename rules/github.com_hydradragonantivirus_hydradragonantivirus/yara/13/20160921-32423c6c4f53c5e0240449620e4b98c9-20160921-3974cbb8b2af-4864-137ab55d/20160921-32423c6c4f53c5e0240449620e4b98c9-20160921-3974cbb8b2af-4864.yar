rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4864 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash4       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "\"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s2 = "f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000" ascii
    $s4 = "){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(" ascii
    $s5 = "turn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}