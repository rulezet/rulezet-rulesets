rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_95ced062e055_5478 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash3       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash4       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash5       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "n \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s2 = "nction f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s4 = "00(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\"" ascii
    $s5 = "n f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}