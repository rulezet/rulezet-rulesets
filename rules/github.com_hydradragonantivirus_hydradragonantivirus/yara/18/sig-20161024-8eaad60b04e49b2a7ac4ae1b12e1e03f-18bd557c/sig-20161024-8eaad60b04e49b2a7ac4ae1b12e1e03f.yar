rule sig_20161024_8eaad60b04e49b2a7ac4ae1b12e1e03f {
  meta:
    description = "datamaliciousorder - file 20161024_8eaad60b04e49b2a7ac4ae1b12e1e03f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e20f674f3142dab47081685f77ef5704c49b08ce5baba435e4a8cfb139dcf7f"

  strings:
    $s1 = "} while (ak++ < nr0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}