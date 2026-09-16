rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_9c9fcc818a70_5327 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash3       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "ion f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s2 = "Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s3 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000" ascii
    $s4 = " f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5 = "{return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}