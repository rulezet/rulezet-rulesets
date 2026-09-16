rule sig_20161024_2524307feb8aa5d918d69a4d0e8ca029 {
  meta:
    description = "datamaliciousorder - file 20161024_2524307feb8aa5d918d69a4d0e8ca029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1790937053854c51db3939effbe7652da2ca1afbc54525f1f69da1f9cf26fc"

  strings:
    $s1 = "} while (mx++ < sy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}