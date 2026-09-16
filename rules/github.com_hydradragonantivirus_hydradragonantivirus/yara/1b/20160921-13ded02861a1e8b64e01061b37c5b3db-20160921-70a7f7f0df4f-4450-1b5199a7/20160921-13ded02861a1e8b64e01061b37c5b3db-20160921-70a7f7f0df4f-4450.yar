rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_70a7f7f0df4f_4450 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"

  strings:
    $s1 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu" ascii
    $s2 = "\"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3 = "eturn \"SEo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})()," ascii
    $s4 = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000()" ascii
    $s5 = "})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}