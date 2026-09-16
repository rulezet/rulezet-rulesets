rule sig_20161024_b4d691bb47f915a0a5c9df4e61705e61 {
  meta:
    description = "datamaliciousorder - file 20161024_b4d691bb47f915a0a5c9df4e61705e61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b9f5e540643a6f91a1dcb485c6d09707e55c750f4b4266c0466acd6c28c5acd"

  strings:
    $s1 = "} while (ob++ < zt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}