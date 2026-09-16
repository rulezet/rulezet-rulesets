rule sig_20160822_545a560701ec3f5f42cdd7c9351d514f {
  meta:
    description = "datamaliciousorder - file 20160822_545a560701ec3f5f42cdd7c9351d514f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4218c97e86965499d2efb5d60ee950812b97a33b34b9167af314bd5e7e36c6dc"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}