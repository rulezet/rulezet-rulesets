rule sig_20160525_f5a2bec486032c0db83f7acf04821e60 {
  meta:
    description = "datamaliciousorder - file 20160525_f5a2bec486032c0db83f7acf04821e60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6941dc71674b635ed409c3a5e45231ce76b57998010fcc7822d56acb2a2bcfca"

  strings:
    $s1 = "3(]\"tArah\"+\"36x\\\\\"+\"\"[suidarelcitrapm = keppelm rav;\"M1yARH\" = suidarelcitrapm rav\\n;\"t96x\\\\sop\" = modnarm rav\\n" ascii
    $s2 = "ixodj nruter{)eixodj(imi noitcnuf;};cthi nruter{)cthi(tsilslianbmuhtoi noitcnuf;};ssorcai nruter{)ssorcai(sdneti noitcnuf;};deer" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}