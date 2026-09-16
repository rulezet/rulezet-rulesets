rule sig_20161024_7a222d830dd7c538825305ec91cf285c {
  meta:
    description = "datamaliciousorder - file 20161024_7a222d830dd7c538825305ec91cf285c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "722e9b740d2291294bbfc30f2ea6545963dab3bb0e18cb1a3a92f7fdf1102b64"

  strings:
    $s1 = "} while (hp0++ < zk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}