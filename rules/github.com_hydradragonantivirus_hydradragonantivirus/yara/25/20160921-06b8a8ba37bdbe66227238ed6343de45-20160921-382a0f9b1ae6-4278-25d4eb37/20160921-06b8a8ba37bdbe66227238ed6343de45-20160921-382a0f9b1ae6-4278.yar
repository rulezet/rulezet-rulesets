rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_382a0f9b1ae6_4278 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash4       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash5       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash6       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash7       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash8       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash9       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"
    hash10      = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash11      = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";" ascii
    $s2 = "WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s3 = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s4 = "00(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\"" ascii
    $s5 = "n \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}