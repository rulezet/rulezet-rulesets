rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_1c5a439961f0_1182 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash3       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash4       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash5       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash6       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash7       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash8       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash9       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash10      = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash11      = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"
    hash12      = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash13      = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash14      = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash15      = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash16      = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash17      = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1  = "Jm\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s2  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(fun" ascii
    $s3  = "rn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(fu" ascii
    $s4  = "on f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return " ascii
    $s5  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(functi" ascii
    $s6  = "rn \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s7  = "eturn \"ZIi\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s8  = "ion f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s9  = "tion f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s10 = "),(function f000(){return \"MOc\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii
    $s11 = "f000(){return \"Ml\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s12 = "0(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s13 = "){return \"Br\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})" ascii
    $s14 = " f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"" ascii
    $s15 = "nction f000(){return \"Rh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s16 = "function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}