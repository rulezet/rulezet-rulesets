rule sig_20161024_3c7b9f66fa9fabf00b9ed0e2ba6d2e5b {
  meta:
    description = "datamaliciousorder - file 20161024_3c7b9f66fa9fabf00b9ed0e2ba6d2e5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01968239aed540eb524e6aa327ecfa12b3d67a5236dc99063e799e304e0adbe4"

  strings:
    $s1 = "} while (mt++ < pt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}