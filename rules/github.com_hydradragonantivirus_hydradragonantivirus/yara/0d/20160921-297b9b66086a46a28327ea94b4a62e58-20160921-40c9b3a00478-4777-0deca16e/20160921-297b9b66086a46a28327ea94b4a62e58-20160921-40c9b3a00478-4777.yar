rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_4777 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s2 = ",(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s3 = "eturn \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"PTs\";})()" ascii
    $s4 = "rn \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(f" ascii
    $s5 = "n f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}