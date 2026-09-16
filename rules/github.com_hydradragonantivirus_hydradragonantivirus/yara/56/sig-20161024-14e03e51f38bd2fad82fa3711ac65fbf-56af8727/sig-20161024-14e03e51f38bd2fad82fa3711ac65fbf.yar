rule sig_20161024_14e03e51f38bd2fad82fa3711ac65fbf {
  meta:
    description = "datamaliciousorder - file 20161024_14e03e51f38bd2fad82fa3711ac65fbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f96c5a72c69f219b307668349fa324a85de5594011b92e1c4f58e25a1f25f154"

  strings:
    $s1 = "} while (gh++ < zp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}