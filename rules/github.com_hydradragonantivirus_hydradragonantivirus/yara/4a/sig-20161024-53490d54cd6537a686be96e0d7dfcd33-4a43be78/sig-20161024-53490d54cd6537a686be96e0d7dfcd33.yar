rule sig_20161024_53490d54cd6537a686be96e0d7dfcd33 {
  meta:
    description = "datamaliciousorder - file 20161024_53490d54cd6537a686be96e0d7dfcd33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e10a424a492c38ce024bc59cf3d83ea046b4d8df5bd9215797100ea75bc7841b"

  strings:
    $s1 = "} while (ex0++ < vo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}