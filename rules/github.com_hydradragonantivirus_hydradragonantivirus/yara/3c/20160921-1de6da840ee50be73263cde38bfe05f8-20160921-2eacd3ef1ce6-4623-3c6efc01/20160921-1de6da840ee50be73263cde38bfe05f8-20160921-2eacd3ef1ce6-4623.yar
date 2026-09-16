rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_4623 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"

  strings:
    $s1 = "{return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(" ascii
    $s2 = "\"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s3 = "g\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s4 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s5 = "n \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}