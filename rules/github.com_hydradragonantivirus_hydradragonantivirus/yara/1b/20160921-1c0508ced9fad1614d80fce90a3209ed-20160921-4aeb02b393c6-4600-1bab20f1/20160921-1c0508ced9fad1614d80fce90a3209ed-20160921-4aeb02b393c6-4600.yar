rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_4aeb02b393c6_4600 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash4       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1 = "turn \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s2 = "RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4 = "0(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\"" ascii
    $s5 = "unction f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}