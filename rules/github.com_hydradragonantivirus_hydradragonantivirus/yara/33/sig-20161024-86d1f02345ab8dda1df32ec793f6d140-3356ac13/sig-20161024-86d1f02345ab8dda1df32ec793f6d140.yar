rule sig_20161024_86d1f02345ab8dda1df32ec793f6d140 {
  meta:
    description = "datamaliciousorder - file 20161024_86d1f02345ab8dda1df32ec793f6d140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e72f09d2a0e548824c33a53138ffe56b1e24ab771258062c99665851d767cde0"

  strings:
    $s1 = "} while (uq++ < dm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}