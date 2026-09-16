rule sig_20160525_89ba120152357fb19a77247b60dde77e {
  meta:
    description = "datamaliciousorder - file 20160525_89ba120152357fb19a77247b60dde77e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfc0af8e7bef884d84e4c1784355aa7716e282a3defd01dcafee7454a7afb4b"

  strings:
    $s1 = "\\n;))keppell(deerdl + gedotdarl + ml + ))(};dnenoisillocl nruter{)(modnarl noitcnuf( + suidarelcitrapl(]ssorcaf + sdnetf + )dee" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}