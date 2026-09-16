rule sig_20161024_05f1724002076f3770a3bcc79792525f {
  meta:
    description = "datamaliciousorder - file 20161024_05f1724002076f3770a3bcc79792525f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d3cd652c8cf5c810f37cdacdb1424b4e59218eeb179d5ef5b5e0a97c4460ed"

  strings:
    $s1 = "} while (hu++ < sq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}