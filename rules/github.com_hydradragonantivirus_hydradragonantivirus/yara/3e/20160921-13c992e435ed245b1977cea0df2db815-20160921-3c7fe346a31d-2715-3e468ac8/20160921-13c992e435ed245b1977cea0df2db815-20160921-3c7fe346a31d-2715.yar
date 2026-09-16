rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_3c7fe346a31d_2715 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh" ascii
    $s3 = "0(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s4 = ")(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(" ascii
    $s5 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s6 = "f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GG" ascii
    $s7 = "n \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}