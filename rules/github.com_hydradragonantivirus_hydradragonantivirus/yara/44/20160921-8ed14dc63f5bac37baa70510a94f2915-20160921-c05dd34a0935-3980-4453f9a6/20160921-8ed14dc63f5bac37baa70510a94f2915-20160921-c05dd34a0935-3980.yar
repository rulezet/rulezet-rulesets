rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_c05dd34a0935_3980 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash3       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash4       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash5       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash6       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){" ascii
    $s2 = "00(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";" ascii
    $s3 = " \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(func" ascii
    $s4 = "on f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"" ascii
    $s5 = "nction f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s6 = "return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}