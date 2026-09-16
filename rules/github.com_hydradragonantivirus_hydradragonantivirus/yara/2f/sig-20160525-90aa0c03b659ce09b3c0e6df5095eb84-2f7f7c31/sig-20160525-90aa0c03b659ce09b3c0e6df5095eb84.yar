rule sig_20160525_90aa0c03b659ce09b3c0e6df5095eb84 {
  meta:
    description = "datamaliciousorder - file 20160525_90aa0c03b659ce09b3c0e6df5095eb84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86c115cebf8850cead954c7822e557aef856a1f1b66e5f41d33101e40012ef0c"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii
    $s2 = "traps = ms rav;\"eJ\" = suidarelcitraps rav\\n;\"86x\\\\C\" = gedotdars rav\\n;\"s27x\\\\a\" = keppels rav\\n;\"47x\\\\e\" = eca" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}