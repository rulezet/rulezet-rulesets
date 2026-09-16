rule sig_20160525_68459e950a6ef1c77e48051abd9f521b {
  meta:
    description = "datamaliciousorder - file 20160525_68459e950a6ef1c77e48051abd9f521b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9da850648d0d68e16fdee92c1de958ffbbe399a49d2ad0770d14317a7e991b8e"

  strings:
    $s1 = "anbmuhton rav\\n;\"45x\\\\ev\" = cthn rav\\n;\"Ff6x\\\\\" = rerednern rav\\n;\"56x\\\\li\" = imn rav;};dnenoisilloco nruter{)dne" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}