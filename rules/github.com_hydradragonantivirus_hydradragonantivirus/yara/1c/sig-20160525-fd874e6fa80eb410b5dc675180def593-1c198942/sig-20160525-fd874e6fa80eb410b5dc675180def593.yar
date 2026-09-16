rule sig_20160525_fd874e6fa80eb410b5dc675180def593 {
  meta:
    description = "datamaliciousorder - file 20160525_fd874e6fa80eb410b5dc675180def593.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "864bbe3e0a6b1869e0915ca86a33e88fcea207c95143b43789de987a5ccd0bad"

  strings:
    $s1 = "n;\"y47x\\\\\" = tsilslianbmuhtol rav\\n;\"56x\\\\p\" = cthl rav;};iml nruter{)iml(rerednerl noitcnuf\\n;\"t96x\\\\rw\" = gsmm r" ascii
    $s2 = "\\\\\" = keppelm rav\\n;)3(]\"tArah\"+\"36x\\\\\"+\"\"[dnenoisillocm = ecapsetihwxelfm rav;\"M1yARH\" = dnenoisillocm rav\\n;\"t" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}