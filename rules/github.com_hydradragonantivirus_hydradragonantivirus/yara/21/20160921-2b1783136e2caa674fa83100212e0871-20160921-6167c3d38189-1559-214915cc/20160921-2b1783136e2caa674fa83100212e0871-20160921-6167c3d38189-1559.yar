rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_1559 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "0(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\"" ascii
    $s2  = "n \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s3  = "tion f000(){return \"Lp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s4  = "return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(" ascii
    $s5  = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s6  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"" ascii
    $s7  = "00(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s8  = "ion f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s9  = "Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s10 = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f00" ascii
    $s11 = "000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s12 = ")(),(function f000(){return \"DNa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}