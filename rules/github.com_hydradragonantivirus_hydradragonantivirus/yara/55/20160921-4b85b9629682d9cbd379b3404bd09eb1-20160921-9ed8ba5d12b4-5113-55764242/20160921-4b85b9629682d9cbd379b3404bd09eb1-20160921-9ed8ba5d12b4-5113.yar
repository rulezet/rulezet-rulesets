rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_9ed8ba5d12b4_5113 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";}" ascii
    $s2 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(funct" ascii
    $s3 = "){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s4 = "Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(functio" ascii
    $s5 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}