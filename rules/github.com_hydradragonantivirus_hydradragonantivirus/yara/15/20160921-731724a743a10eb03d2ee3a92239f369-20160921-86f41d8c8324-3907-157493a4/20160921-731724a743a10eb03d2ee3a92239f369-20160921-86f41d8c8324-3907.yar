rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_86f41d8c8324_3907 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash3       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash4       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "00(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv" ascii
    $s2 = ";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f" ascii
    $s3 = "return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})()" ascii
    $s4 = "(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";" ascii
    $s5 = "WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(functi" ascii
    $s6 = "function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}