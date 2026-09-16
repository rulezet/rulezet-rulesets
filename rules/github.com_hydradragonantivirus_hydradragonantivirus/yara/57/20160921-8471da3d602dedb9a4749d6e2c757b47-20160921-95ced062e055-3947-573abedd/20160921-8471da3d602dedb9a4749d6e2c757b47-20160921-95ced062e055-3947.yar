rule _20160921_8471da3d602dedb9a4749d6e2c757b47_20160921_95ced062e055_3947 {
  meta:
    description = "datamaliciousorder - from files 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash3       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash4       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash5       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash6       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash7       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "n \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s2 = "\"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s3 = "tion f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){retur" ascii
    $s4 = "n f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"" ascii
    $s5 = "turn \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})()," ascii
    $s6 = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}