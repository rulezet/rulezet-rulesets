rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4871 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1 = "function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){re" ascii
    $s2 = "function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s3 = " f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = " f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii
    $s5 = "(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}