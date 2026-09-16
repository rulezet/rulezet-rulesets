rule sig_20161024_9dfa71ff70c383964f758df0cc3537f9 {
  meta:
    description = "datamaliciousorder - file 20161024_9dfa71ff70c383964f758df0cc3537f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28767e996446f4ea7eb28ccfc6b8b80e28f6d774f13ccc3277f54ad919444c6c"

  strings:
    $s1 = "} while (ef++ < fv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}