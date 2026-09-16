rule _20160921_95ced062e0552048d29cf59daab852db_20160921_c6543124cf42_5560 {
  meta:
    description = "datamaliciousorder - from files 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash2       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash3       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash4       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash5       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"
    hash6       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(fun" ascii
    $s3 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s4 = "){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})" ascii
    $s5 = "){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}