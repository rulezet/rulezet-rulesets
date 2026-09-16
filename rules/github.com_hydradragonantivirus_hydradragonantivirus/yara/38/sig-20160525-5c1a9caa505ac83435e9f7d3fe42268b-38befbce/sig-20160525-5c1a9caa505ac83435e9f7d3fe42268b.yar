rule sig_20160525_5c1a9caa505ac83435e9f7d3fe42268b {
  meta:
    description = "datamaliciousorder - file 20160525_5c1a9caa505ac83435e9f7d3fe42268b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0b4fe8cc6e60a1f297440cc581f2ff1360807690698f9d7a306e53c854468fe"

  strings:
    $s1 = "\\\\f6x\\\\63x\\\\\" = rerednero rav\\n;\"dsv16x\\\\\" = imo rav\\n;\"35x\\\\Xv\" = eixodp rav\\n;\"iOa4x\\\\B17x\\\\\" = gsmp r" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}