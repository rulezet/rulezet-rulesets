rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_202394e6610d_4615 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash3       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash4       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash5       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = "00(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\"" ascii
    $s2 = " \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s3 = "return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})()" ascii
    $s4 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\"" ascii
    $s5 = "on f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}