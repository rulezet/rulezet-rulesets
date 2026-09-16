rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_e985c90f8141_4957 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = "urn \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(f" ascii
    $s2 = "(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s3 = "turn \"Oh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\"" ascii
    $s5 = " \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}