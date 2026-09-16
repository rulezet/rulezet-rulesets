rule sig_20160525_641ac5758ceb51e3bf3107a15f6d157b {
  meta:
    description = "datamaliciousorder - file 20160525_641ac5758ceb51e3bf3107a15f6d157b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48f182be71d56e791b71a9fba8e5492e6f358aabe3170009ccc7d32485447bd1"

  strings:
    $s1 = "odnarj + ))(};ecapsetihwxelfj nruter{)(sdnetj noitcnuf( + ))(};keppelj nruter{)(deerdj noitcnuf( ,mj + dnenoisillocj + ))(};suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}