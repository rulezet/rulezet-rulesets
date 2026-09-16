rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_1c739a510b20_4211 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_dd42e850834f3af27a08edf609a699b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash4       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"

  strings:
    $s1 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})" ascii
    $s3 = "(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\"" ascii
    $s4 = "ion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return " ascii
    $s5 = "\"ILp\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}