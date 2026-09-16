rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_e30a7fc515c8_4388 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash3       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = ")(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(" ascii
    $s2 = "000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe" ascii
    $s3 = "0(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\"" ascii
    $s4 = "rn \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s5 = "\"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}