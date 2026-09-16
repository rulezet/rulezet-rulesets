rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_3602 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "nction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s2 = ",(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii
    $s3 = "f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TR" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s5 = "n f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s6 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}