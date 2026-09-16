rule sig_20160525_04f8653d1af88b40df138dc18e9cbfb6 {
  meta:
    description = "datamaliciousorder - file 20160525_04f8653d1af88b40df138dc18e9cbfb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ac6760ee7172f197fb1c977c4bf0226b0a686d54d37f3a36a32b3804027914c"

  strings:
    $s1 = "lock rav\\n;\"t76x\\\\e6x\\\\\" = mk rav\\n;)1(]\"tAra\"+\"86x\\\\\"+\"c\"[suidarelcitrapk = gedotdark rav;\"f9hE\" = suidarelci" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}