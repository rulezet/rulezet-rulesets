rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_69015d5cf863_4618 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})()," ascii
    $s2 = "{return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";}" ascii
    $s3 = "function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s4 = "00(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt" ascii
    $s5 = "ction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}