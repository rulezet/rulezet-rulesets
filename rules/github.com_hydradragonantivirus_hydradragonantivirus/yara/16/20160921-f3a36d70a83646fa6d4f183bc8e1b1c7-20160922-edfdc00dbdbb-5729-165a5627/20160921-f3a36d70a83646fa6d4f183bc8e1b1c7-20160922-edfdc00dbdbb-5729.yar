rule _20160921_f3a36d70a83646fa6d4f183bc8e1b1c7_20160922_edfdc00dbdbb_5729 {
  meta:
    description = "datamaliciousorder - from files 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = ")(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})(),(function f000" ascii
    $s2 = "n \"Sj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(func" ascii
    $s3 = "n f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii
    $s4 = "(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){ret" ascii
    $s5 = "rn \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}