rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_d74d6a32efd0_4444 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = " f000(){return \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu" ascii
    $s2 = ";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f0" ascii
    $s3 = "n f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "n \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}