rule _20160921_be923844637026740bc9e5a4aad21ebe_20160921_c10352a0b5ce_5671 {
  meta:
    description = "datamaliciousorder - from files 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_c10352a0b5ce476f023184a502920234.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash3       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "unction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s2 = "turn \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "Xg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s4 = "000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\"" ascii
    $s5 = "{return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}