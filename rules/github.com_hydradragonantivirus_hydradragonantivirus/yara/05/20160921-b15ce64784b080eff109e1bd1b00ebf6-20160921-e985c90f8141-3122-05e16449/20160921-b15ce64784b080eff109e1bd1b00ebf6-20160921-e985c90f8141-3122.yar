rule _20160921_b15ce64784b080eff109e1bd1b00ebf6_20160921_e985c90f8141_3122 {
  meta:
    description = "datamaliciousorder - from files 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_e985c90f8141417e484ad0056c9b809c.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash2       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"
    hash3       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1 = "){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})" ascii
    $s2 = "ion f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WI" ascii
    $s4 = "(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(" ascii
    $s6 = " f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s7 = "h\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}