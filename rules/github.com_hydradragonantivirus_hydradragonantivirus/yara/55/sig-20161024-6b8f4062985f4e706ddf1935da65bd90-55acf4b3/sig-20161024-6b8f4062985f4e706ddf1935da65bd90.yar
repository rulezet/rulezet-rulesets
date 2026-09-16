rule sig_20161024_6b8f4062985f4e706ddf1935da65bd90 {
  meta:
    description = "datamaliciousorder - file 20161024_6b8f4062985f4e706ddf1935da65bd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7206e01721a29c595a557baade2ab794911a7e9d9d7d22a832584c8211416af6"

  strings:
    $s1 = "} while (yk++ < gi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}