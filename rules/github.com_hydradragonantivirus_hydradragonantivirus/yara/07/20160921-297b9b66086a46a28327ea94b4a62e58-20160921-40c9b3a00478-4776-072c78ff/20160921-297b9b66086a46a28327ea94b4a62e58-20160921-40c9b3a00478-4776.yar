rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_4776 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "0(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";" ascii
    $s2 = "Gn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s3 = "ion f000(){return \"BIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s4 = " f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go" ascii
    $s5 = "return \"QDg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}