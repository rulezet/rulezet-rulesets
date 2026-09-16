rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_16200453422b_757 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_7706788d60398ea7d883afb2532d218f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash3       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash4       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash5       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash6       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash7       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash8       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash9       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash10      = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash11      = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash12      = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash13      = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash14      = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash15      = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash16      = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash17      = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash18      = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash19      = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"
    hash20      = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s2  = "{return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s4  = "eturn \"Sv\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s6  = "urn \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s7  = "tion f000(){return \"Qa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s8  = "){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})(" ascii
    $s9  = "s\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s10 = "})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"EZu\";})(),(function f00" ascii
    $s11 = "turn \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s12 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s13 = "nction f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s14 = "function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){retu" ascii
    $s15 = "unction f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Go\";})(),(function f000(){ret" ascii
    $s16 = "tion f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){retur" ascii
    $s17 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nx\";})(),(function f00" ascii
    $s18 = "(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s19 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IPu\";})(),(fun" ascii
    $s20 = "Tp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}