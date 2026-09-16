rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_3681 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash4       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sv\";})()" ascii
    $s2 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"KDh\";})(),(function f000" ascii
    $s3 = "00(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s4 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s5 = " f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"T" ascii
    $s6 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}