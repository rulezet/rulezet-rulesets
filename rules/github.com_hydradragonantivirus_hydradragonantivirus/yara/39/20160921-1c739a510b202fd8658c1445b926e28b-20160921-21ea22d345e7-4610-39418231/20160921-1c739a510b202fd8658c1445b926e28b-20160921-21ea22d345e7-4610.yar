rule _20160921_1c739a510b202fd8658c1445b926e28b_20160921_21ea22d345e7_4610 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c739a510b202fd8658c1445b926e28b.js, 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_dd42e850834f3af27a08edf609a699b5.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5e44b6b8f05f9e4eadc507955ef770936acdd360f7dcfe6bb70a36427b04b7"
    hash2       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash3       = "d7708087ab30a8d0d937f9d460512c05c37534c0d3c387bd3e1dd7fcb84fdc58"
    hash4       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LG" ascii
    $s2 = "uck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s4 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XFd" ascii
    $s5 = "return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}