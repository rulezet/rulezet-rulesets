rule sig_20160525_09e98de543e75cd8999f2c36e1917832 {
  meta:
    description = "datamaliciousorder - file 20160525_09e98de543e75cd8999f2c36e1917832.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab0409d4fdf93d924d9c29497204bc61c77fe7857e371aaf220967f27ed02c79"

  strings:
    $s1 = "rape nruter{)suidarelcitrape(gsme noitcnuf\\n;\"1f2x\\\\\" = dnenoisilloce rav\\n;\"x13x\\\\5\" = me rav\\n;\"d6x\\\\\" = gedotd" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}