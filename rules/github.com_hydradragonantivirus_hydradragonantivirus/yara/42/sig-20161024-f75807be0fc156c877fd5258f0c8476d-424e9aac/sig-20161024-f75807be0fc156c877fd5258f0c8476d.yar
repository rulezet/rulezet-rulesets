rule sig_20161024_f75807be0fc156c877fd5258f0c8476d {
  meta:
    description = "datamaliciousorder - file 20161024_f75807be0fc156c877fd5258f0c8476d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d94a8456b33b1115312b22be7e658ddcfee26ac39e75abb4654c04af894c9dcb"

  strings:
    $s1 = "} while (qe0++ < go);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}