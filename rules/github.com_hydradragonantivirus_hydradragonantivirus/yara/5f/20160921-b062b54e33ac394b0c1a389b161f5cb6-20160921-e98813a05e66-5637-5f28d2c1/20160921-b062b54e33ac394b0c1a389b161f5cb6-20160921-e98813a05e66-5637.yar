rule _20160921_b062b54e33ac394b0c1a389b161f5cb6_20160921_e98813a05e66_5637 {
  meta:
    description = "datamaliciousorder - from files 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s2 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(f" ascii
    $s3 = "urn \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s4 = "urn \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = "),(function f000(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}