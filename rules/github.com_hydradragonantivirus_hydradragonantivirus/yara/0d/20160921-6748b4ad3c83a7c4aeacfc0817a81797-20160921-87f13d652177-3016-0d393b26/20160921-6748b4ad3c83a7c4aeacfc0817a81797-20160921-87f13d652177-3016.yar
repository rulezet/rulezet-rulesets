rule _20160921_6748b4ad3c83a7c4aeacfc0817a81797_20160921_87f13d652177_3016 {
  meta:
    description = "datamaliciousorder - from files 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = "Dg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s2 = "function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s3 = "})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s5 = "urn \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(" ascii
    $s6 = "return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s7 = "unction f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}