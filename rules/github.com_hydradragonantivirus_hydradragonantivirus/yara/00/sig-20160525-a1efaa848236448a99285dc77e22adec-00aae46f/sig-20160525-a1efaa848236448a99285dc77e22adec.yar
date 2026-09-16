rule sig_20160525_a1efaa848236448a99285dc77e22adec {
  meta:
    description = "datamaliciousorder - file 20160525_a1efaa848236448a99285dc77e22adec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b35e9695f18397a0d5c686d348c2a3c6618e23a8a6b9440acdb83320236651c"

  strings:
    $s1 = "neti nruter{)sdneti(deerdi noitcnuf\\n;\"r34x\\\\\" = suidarelcitrapj rav\\n;\"f4x\\\\e47x\\\\16x\\\\56x\\\\\" = dnenoisillocj r" ascii
    $s2 = "\\\\\" = gedotdarv rav\\n;\"ht76x\\\\n\" = keppelv rav\\n;\"gn56x\\\\l\" = ecapsetihwxelfv rav\\n;\"h47x\\\\\" = modnarv rav'[\"" ascii
    $s3 = "\"36x\\\\\"+\"\"[me = keppele rav;\"/0\" = me rav\\n;\"726x\\\\\" = ecapsetihwxelfe rav\\n;\"36x\\\\4\" = modnare rav;};sdnete n" ascii
    $s4 = "gsmn = mn rav;\"Pe\" = gsmn rav\\n;\"nec6x\\\\\" = ecapsetihwxelfn rav\\n;\"h47x\\\\g\" = modnarn rav\\n;\"t76x\\\\nel\" = sdnet" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}