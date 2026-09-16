rule sig_20160525_33c0ebe44551875b458ac1fabc718f5c {
  meta:
    description = "datamaliciousorder - file 20160525_33c0ebe44551875b458ac1fabc718f5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4303bb88ef1090b11f6e2174bacfb9baeeab4ba7c1eaf867c7f067a7b728c300"

  strings:
    $s1 = "x\\\\ec6x\\\\S\" = ssorcak rav;};rerednerk nruter{)rerednerk(cthk noitcnuf\\n;\"ne07x\\\\f6x\\\\\" = imk rav\\n;\"T54x\\\\G\" = " ascii
    $s2 = "nruter{)modnarm(ecapsetihwxelfm noitcnuf;};keppelm nruter{)keppelm(gedotdarm noitcnuf;};dnenoisillocm nruter{)dnenoisillocm(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}