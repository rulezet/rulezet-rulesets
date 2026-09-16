rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160922_edfdc00dbdbb_5523 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "0(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\"" ascii
    $s2 = "unction f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s3 = "t\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function" ascii
    $s4 = "unction f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s5 = "){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}