rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_4122 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_8d22ed47876b303a1415a88483556238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"

  strings:
    $s1 = "function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s2 = "(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){re" ascii
    $s3 = "(){return \"Iq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})" ascii
    $s4 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo" ascii
    $s5 = "KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}