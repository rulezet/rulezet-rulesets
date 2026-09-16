rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_297b9b66086a_4346 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash4       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash5       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "n f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2 = "{return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})()" ascii
    $s3 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s4 = "v\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s5 = "){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"DNa\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}