rule sig_20170504_dcaac8421d5e1e2d47883d3cd73920b6 {
  meta:
    description = "datamaliciousorder - file 20170504_dcaac8421d5e1e2d47883d3cd73920b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d02b284347cce4968fae3ee2410ba02eca48d1b27c9362625bd8d67b7bca1db"

  strings:
    $s1 = "this[\"\\145\\u0076\\141\\x6c\"](\"n\\145\\u0077\\40\\u0041\\u0063tiv\\u0065\\x58\\x4f\\x62j\\x65\\143\\u0074\\50\\42\\127Sc\\x7" ascii
    $s2 = "this[\"\\145\\u0076\\141\\x6c\"](\"n\\145\\u0077\\40\\u0041\\u0063tiv\\u0065\\x58\\x4f\\x62j\\x65\\143\\u0074\\50\\42\\127Sc\\x7" ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}