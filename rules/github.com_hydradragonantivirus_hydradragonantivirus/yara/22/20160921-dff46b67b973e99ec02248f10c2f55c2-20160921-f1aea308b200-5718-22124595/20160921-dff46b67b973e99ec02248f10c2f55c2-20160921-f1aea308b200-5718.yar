rule _20160921_dff46b67b973e99ec02248f10c2f55c2_20160921_f1aea308b200_5718 {
  meta:
    description = "datamaliciousorder - from files 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s2 = "o\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s3 = "\"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(funct" ascii
    $s4 = "00(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn" ascii
    $s5 = "(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}