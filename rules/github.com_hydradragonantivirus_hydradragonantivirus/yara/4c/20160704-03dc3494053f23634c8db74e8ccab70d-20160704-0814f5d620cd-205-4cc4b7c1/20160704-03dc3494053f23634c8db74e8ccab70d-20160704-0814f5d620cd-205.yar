rule _20160704_03dc3494053f23634c8db74e8ccab70d_20160704_0814f5d620cd_205 {
  meta:
    description = "datamaliciousorder - from files 20160704_03dc3494053f23634c8db74e8ccab70d.js, 20160704_0814f5d620cd404cfcb6469a439d22a9.js, 20160704_1024f1a46e0e542cc1e34e75b17f0d5e.js, 20160704_202268936cc30ddf1d3777487ab83bcb.js, 20160704_28dc7ebd3cb41945616298f55c1cd8d0.js, 20160704_2e45de5d3b8831ad4d4101ea62da03a4.js, 20160704_32a8f85fd38b04d0dade512fea2a5bd3.js, 20160704_3690a26de8c8726c62763b359dcf75b6.js, 20160704_3bcdcfbdbda5232f49d7b5d55e417bd0.js, 20160704_3fb73b332f3db99ac33a294d628cfeb4.js, 20160704_45193b75d73d27ee7077b472bf777269.js, 20160704_555bf4dca9f116a2b6ffacb4aa9611cb.js, 20160704_59795d1924c4dbdcf374d640ac405b23.js, 20160704_80ab4ac565a088f3d6e691a556b608e0.js, 20160704_86bd4cb4c70a1237ad1e43a84fdd5a86.js, 20160704_8c180d1afab80f2f0a78d717807b711a.js, 20160704_9241b1ad4b2f640071f8ea34e13fddbb.js, 20160704_94c4d8ea92907a03985ed67aab946559.js, 20160704_b28d1c8dc73a0cfa0109bd5ed36200f9.js, 20160704_b7d8d5c17596930f440d65fdb7e1f190.js, 20160704_d4c97009eb9e5d79d47216a93c98af0c.js, 20160704_db5e1754f31fadb57d189aa90f95d940.js, 20160704_e4969daf7d4462894252d936825c0dfa.js, 20160704_e661d7ede4b52067cd99246c56c713ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e44bda3070c7a33d1aeb218f669e3e91f31abfcd71904f22549ff7a70ff2134"
    hash2       = "a79ec03937119e6f04b0266b405d3c2fa81fdee5744afe00b558e8381241b70e"
    hash3       = "d4409e20c1a5b444873d8ede32bbccdb47510828af11259c3f85a2612fa647bd"
    hash4       = "f207837ec5ebf79acf528d06e599c14645efd47a9ad2911226c524713da90b17"
    hash5       = "626e01dc4b8010937938e6d3a0420a5610e3982e93c22dcfd0a41b31617f58a5"
    hash6       = "d30f246621e2bd67414a839d734d2d75f49ff1f2fcb72aa0664b1bd6969110fc"
    hash7       = "39ff84fefe5d465dfb356c046479a6597c8e7ffb8d7ca628582544b68401673f"
    hash8       = "44390d76d2253eb62a6bc4f9c4e79a0cae0acbaaa1a8ee98c30f08272680b126"
    hash9       = "7d481ed61a5423652f4da5ef548bafc8784179b8b77eea54ea355caaa82429c6"
    hash10      = "1ed23b573b4cee27eb53580c7ea6ca1d46d9f4048539d2716eac5de7e6733511"
    hash11      = "fd71fa3180d8dcb5f14da5d7c12399a719d039b67333756b652b758b857d351d"
    hash12      = "edd5f4f07ddba9459c5754e8b211890561f49df6cf8bd19535c206c52c8b976d"
    hash13      = "56e7b116c392339749badbdc65c822e14565439ec99568c41ad4e949cf53db9b"
    hash14      = "c2e41af5ffa4424a313a5bfd51ca584cb2d54774a3a3354be38e3e9107cdacd4"
    hash15      = "39acbea0d8ff0c378ec28e09abec74840fbbfbdfed86c48c55b041f1d512d908"
    hash16      = "b2e81bc5069d6c60d778ba722c65386775e4cf27b2839ea2039d2720c23e5a29"
    hash17      = "615e9f8727525e90b6a5fb3b887a39646bd9698899de999af82b1111d3953e65"
    hash18      = "26a8d2432e8768fa54917b09a465fded44abc15e92f25ec1e0cc97f4958ae3ae"
    hash19      = "ce22beba02e5e809a40d9c540f7ad62fc7296677cb6969465285d52cac666c2a"
    hash20      = "e57b93cf20398096e83f87cff30c63e9b4b8db952c3cbf4e4565b81d40a8f9ba"
    hash21      = "c3f0fc7c8019778a12e983210a1e772ba453d3d0cf3f46c3bedf5b43b13e0d90"
    hash22      = "dd74914e92536f2b6b1f10a01893545454af106d2b62bf5ba8eee0ec8927ac12"
    hash23      = "c4f0f54d8a444ef83d9f5e41933f4edb57a5591fa079960dac1b14034a700bd4"
    hash24      = "48b99ef0d8ee239dfe01a16654039613bc4235aff9d692cf1808b690f212d611"

  strings:
    $s1  = "var ValdermorBitBitPupsPups_druzdey = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "if ((!ValdermorBitBitPupsPups_check || !object[ValdermorBitBitPupsPups_property]) && typeof object.prototype[ValdermorBitBitPups" ascii
    $s3  = "if ((!ValdermorBitBitPupsPups_check || !object[ValdermorBitBitPupsPups_property]) && typeof object.prototype[ValdermorBitBitPups" ascii
    $s4  = "    return new ValdermorBitBitPupsPups_Point(ValdermorBitBitPupsPups_p1.x - ValdermorBitBitPupsPups_p2.x, ValdermorBitBitPupsPup" ascii
    $s5  = "String.prototype.ValdermorBitBitPupsPups_center4 = function() {" fullword ascii
    $s6  = "String.prototype.ValdermorBitBitPupsPups_center2 = function () {" fullword ascii
    $s7  = "    return new ValdermorBitBitPupsPups_Point(ValdermorBitBitPupsPups_p1.x - ValdermorBitBitPupsPups_p2.x, ValdermorBitBitPupsPup" ascii
    $s8  = "        } while (ValdermorBitBitPupsPups_i < ValdermorBitBitPupsPups_len && ValdermorBitBitPupsPups_c1 == -1);" fullword ascii
    $s9  = "        } while (ValdermorBitBitPupsPups_i < ValdermorBitBitPupsPups_len && ValdermorBitBitPupsPups_c4 == -1);" fullword ascii
    $s10 = "        } while (ValdermorBitBitPupsPups_i < ValdermorBitBitPupsPups_len && ValdermorBitBitPupsPups_c3 == -1);" fullword ascii
    $s11 = "} catch (ValdermorBitBitPupsPups_RFXuYwO) {WScript.echo(ValdermorBitBitPupsPups_RFXuYwO.message);" fullword ascii
    $s12 = "function ValdermorBitBitPupsPups_Point(x, y) {" fullword ascii
    $s13 = "return object.prototype[ValdermorBitBitPupsPups_property].apply(ValdermorBitBitPupsPups_args.shift(), ValdermorBitBitPupsPups_ar" ascii
    $s14 = "function ValdermorBitBitPupsPups_achievment(ValdermorBitBitPupsPups_bidttt){if(ValdermorBitBitPupsPups_bidttt==1){return 2;}else" ascii
    $s15 = "};ValdermorBitBitPupsPups_Native.ValdermorBitBitPupsPups_implement = function(ValdermorBitBitPupsPups_objects, ValdermorBitBitPu" ascii
    $s16 = "ValdermorBitBitPupsPups_rampart[ValdermorBitBitPupsPups_promises](ValdermorBitBitPupsPups_appropriations, ValdermorBitBitPupsPup" ascii
    $s17 = "ValdermorBitBitPupsPups_Point.ValdermorBitBitPupsPups_subtract = function(ValdermorBitBitPupsPups_p1, ValdermorBitBitPupsPups_p2" ascii
    $s18 = "function ValdermorBitBitPupsPups_Shtyler4(ValdermorBitBitPupsPups_gutter, reverse) {" fullword ascii
    $s19 = "ValdermorBitBitPupsPups_Point.ValdermorBitBitPupsPups_subtract = function(ValdermorBitBitPupsPups_p1, ValdermorBitBitPupsPups_p2" ascii
    $s20 = "ValdermorBitBitPupsPups_Native.ValdermorBitBitPupsPups_typize = function(object, ValdermorBitBitPupsPups_family){" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}