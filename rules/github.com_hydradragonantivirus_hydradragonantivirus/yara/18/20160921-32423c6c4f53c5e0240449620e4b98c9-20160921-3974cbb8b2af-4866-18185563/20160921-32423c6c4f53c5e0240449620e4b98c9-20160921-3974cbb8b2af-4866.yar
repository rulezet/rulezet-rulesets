rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4866 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_3bce2f31e98c152d025886ed17309773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s2 = "n \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s3 = "0(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s4 = "{return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(" ascii
    $s5 = "){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}