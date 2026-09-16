rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_7 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1  = "turn \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(f" ascii
    $s2  = "rn \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(f" ascii
    $s3  = "Fe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s4  = "urn \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"SEo\";})(),(" ascii
    $s5  = "RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s6  = "nction f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s7  = "){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})" ascii
    $s8  = "n f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"G" ascii
    $s9  = "on f000(){return \"Oh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(" ascii
    $s11 = "n f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s12 = "})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s13 = "\"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(funct" ascii
    $s14 = "urn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wb\";})(),(f" ascii
    $s15 = "(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";}" ascii
    $s16 = "return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(" ascii
    $s17 = "Mj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s18 = "tion f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return" ascii
    $s19 = "000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc" ascii
    $s20 = "})(),(function f000(){return \"SEo\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}