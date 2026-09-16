rule sig_20161024_1c6a351940c8109bb05f26067b2bdfed {
  meta:
    description = "datamaliciousorder - file 20161024_1c6a351940c8109bb05f26067b2bdfed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e066035b594606148d6be6e800759cfe1f63d6bacb443aede8a2500845c1ccf8"

  strings:
    $s1 = "} while (jv++ < ks);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}