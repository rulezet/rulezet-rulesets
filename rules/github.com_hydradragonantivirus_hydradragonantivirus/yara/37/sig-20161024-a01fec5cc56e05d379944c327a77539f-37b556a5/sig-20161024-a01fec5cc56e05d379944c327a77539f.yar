rule sig_20161024_a01fec5cc56e05d379944c327a77539f {
  meta:
    description = "datamaliciousorder - file 20161024_a01fec5cc56e05d379944c327a77539f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff714dbcd2e6e9e96af1e6920502af24896f466344d25478ec8fddaaf9456107"

  strings:
    $s1 = "} while (vq++ < fw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}