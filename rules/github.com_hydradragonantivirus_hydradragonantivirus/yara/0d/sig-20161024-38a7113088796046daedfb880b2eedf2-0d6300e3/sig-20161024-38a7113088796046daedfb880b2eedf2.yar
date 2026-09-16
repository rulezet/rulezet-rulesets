rule sig_20161024_38a7113088796046daedfb880b2eedf2 {
  meta:
    description = "datamaliciousorder - file 20161024_38a7113088796046daedfb880b2eedf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c183a1cc8bea027427ecb7372d60e750bac83d78c922d85eed4c4d1aef940388"

  strings:
    $s1 = "} while (cd++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}