rule _20160921_95ced062e0552048d29cf59daab852db_20160921_a39f22c0c39a_3990 {
  meta:
    description = "datamaliciousorder - from files 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash3       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash4       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash5       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f00" ascii
    $s2 = "{return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})" ascii
    $s3 = "(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})" ascii
    $s4 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s5 = "turn \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(fu" ascii
    $s6 = " \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}