rule _20160921_d47b4a8df4397da0f8d93fe0d9eeb14b_20160922_edfdc00dbdbb_3151 {
  meta:
    description = "datamaliciousorder - from files 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s2 = "f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Q" ascii
    $s3 = "f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s4 = "f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s5 = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000" ascii
    $s6 = "tion f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s7 = "(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}