rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_1de6da840ee5_4300 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash3       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash4       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash5       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi" ascii
    $s2 = "n \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(funct" ascii
    $s3 = "0(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";" ascii
    $s4 = "(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s5 = "rn \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}