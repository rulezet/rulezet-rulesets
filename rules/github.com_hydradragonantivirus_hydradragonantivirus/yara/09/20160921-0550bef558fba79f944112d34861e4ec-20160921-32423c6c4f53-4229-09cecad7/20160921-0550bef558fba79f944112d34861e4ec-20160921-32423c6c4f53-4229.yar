rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_32423c6c4f53_4229 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash4       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash5       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s2 = "l\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3 = "RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s5 = "rn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}