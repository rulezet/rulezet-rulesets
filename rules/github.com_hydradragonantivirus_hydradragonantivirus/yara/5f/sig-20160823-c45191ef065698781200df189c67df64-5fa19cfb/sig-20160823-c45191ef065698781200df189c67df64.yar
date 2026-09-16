rule sig_20160823_c45191ef065698781200df189c67df64 {
  meta:
    description = "datamaliciousorder - file 20160823_c45191ef065698781200df189c67df64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39a1bbf329f9de97fc921052e999b61a175a34df699044b4eb99ea3ca0da8c1"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}