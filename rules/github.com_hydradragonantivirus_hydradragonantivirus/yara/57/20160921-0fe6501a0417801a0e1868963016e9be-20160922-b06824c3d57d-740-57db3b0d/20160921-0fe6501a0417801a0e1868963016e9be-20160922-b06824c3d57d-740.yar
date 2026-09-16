rule _20160921_0fe6501a0417801a0e1868963016e9be_20160922_b06824c3d57d_740 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1  = "nction f000(){return \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s2  = "(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(" ascii
    $s3  = "on f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s4  = "n f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"G" ascii
    $s5  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})()" ascii
    $s6  = "ion f000(){return \"Tb\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s7  = "f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj" ascii
    $s8  = "turn \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s9  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"" ascii
    $s10 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s11 = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(" ascii
    $s12 = ")(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s13 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s14 = "return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"WIj\";})()," ascii
    $s15 = "turn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})()," ascii
    $s16 = "eturn \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})()" ascii
    $s17 = "n f000(){return \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s18 = "(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";" ascii
    $s19 = "m\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s20 = "\"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}