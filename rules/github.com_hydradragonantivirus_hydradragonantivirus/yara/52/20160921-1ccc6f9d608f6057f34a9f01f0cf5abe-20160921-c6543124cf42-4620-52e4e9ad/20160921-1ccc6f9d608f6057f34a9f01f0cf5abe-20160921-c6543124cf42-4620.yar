rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_c6543124cf42_4620 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s2 = "\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function f000" ascii
    $s4 = "ction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){retur" ascii
    $s5 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}