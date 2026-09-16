rule sig_20160525_acf6a6534f557a2803caeb70898260aa {
  meta:
    description = "datamaliciousorder - file 20160525_acf6a6534f557a2803caeb70898260aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5d170d9baab07582287ec4897296f019792b5b57564c2902c298485cbbd0aa"

  strings:
    $s1 = "x\\\\T46x\\\\\" = tsilslianbmuhtos rav\\n;\"t87x\\\\\" = cths rav;};ims nruter{)ims(reredners noitcnuf\\n;\"sf6x\\\\lc\" = gsmt " ascii
    $s2 = "i64x\\\\\" = rerednern rav\\n;)0(]\"tAra\"+\"86x\\\\\"+\"c\"[ssorcan = imn rav;\"LAoe\" = ssorcan rav\\n;\"l36x\\\\\" = gsmo rav" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}