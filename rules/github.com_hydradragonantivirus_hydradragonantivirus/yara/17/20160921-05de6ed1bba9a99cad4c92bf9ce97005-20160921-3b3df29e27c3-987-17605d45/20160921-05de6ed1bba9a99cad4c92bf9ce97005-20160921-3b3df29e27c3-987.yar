rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_3b3df29e27c3_987 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash3       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash5       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash6       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash7       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1  = "eturn \"IAa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2  = "Na\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3  = "})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s4  = "n\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f" ascii
    $s5  = "on f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s6  = "function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){re" ascii
    $s7  = "n \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"YTp\";})(),(fun" ascii
    $s8  = "unction f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s9  = "rn \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Vj\";})(),(fun" ascii
    $s10 = "unction f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"HJm\";})(),(function f000(){ret" ascii
    $s11 = "\"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(func" ascii
    $s12 = "),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s13 = "KDh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s14 = "Gn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s15 = "urn \"Tb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s16 = "ion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s17 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})()" ascii
    $s18 = " f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"M" ascii
    $s19 = "{return \"PTs\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}