rule sig_20160525_33f66613d34c60c4e32eada616d90ca6 {
  meta:
    description = "datamaliciousorder - file 20160525_33f66613d34c60c4e32eada616d90ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcf82af2db699126e164f90cbc91949942536436af4a6cd27643f5d230733d5c"

  strings:
    $s1 = "\\n;))keppell(deerdl + gedotdarl + ml + ))(};dnenoisillocl nruter{)(modnarl noitcnuf( + suidarelcitrapl(]ssorcaf + sdnetf + )dee" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}