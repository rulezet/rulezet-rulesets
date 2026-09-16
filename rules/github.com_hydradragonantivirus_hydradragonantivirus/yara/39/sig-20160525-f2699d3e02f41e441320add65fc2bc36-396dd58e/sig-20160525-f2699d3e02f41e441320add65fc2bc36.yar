rule sig_20160525_f2699d3e02f41e441320add65fc2bc36 {
  meta:
    description = "datamaliciousorder - file 20160525_f2699d3e02f41e441320add65fc2bc36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ef4f74fab0c37e9a749efcc4345a6ab4667ebfc2748e1d7e91e47d588b240f8"

  strings:
    $s1 = " modnarm rav\\n;\"47x\\\\g\" = deerdm rav\\n;\"86x\\\\\" = sdnetm rav\\n;\"nec6x\\\\\" = tsilslianbmuhtom rav\\n;\"t76x\\\\\" = " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}