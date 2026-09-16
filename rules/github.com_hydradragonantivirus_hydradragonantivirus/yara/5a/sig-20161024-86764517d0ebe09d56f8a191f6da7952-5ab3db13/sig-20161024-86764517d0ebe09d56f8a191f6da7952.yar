rule sig_20161024_86764517d0ebe09d56f8a191f6da7952 {
  meta:
    description = "datamaliciousorder - file 20161024_86764517d0ebe09d56f8a191f6da7952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f72b8b368148783904a0fbc03bfb0209ce05d7c5a7e729b5ae17bcb4b600d67"

  strings:
    $s1 = "} while (ec++ < uz0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}