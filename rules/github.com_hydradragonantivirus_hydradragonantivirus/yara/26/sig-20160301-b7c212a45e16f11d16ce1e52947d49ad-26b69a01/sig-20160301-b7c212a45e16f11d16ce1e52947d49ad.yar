rule sig_20160301_b7c212a45e16f11d16ce1e52947d49ad {
  meta:
    description = "datamaliciousorder - file 20160301_b7c212a45e16f11d16ce1e52947d49ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33d58eb9e697588e6e112d79b75e501f9a3e431fe679a76bddd3d8de792077c5"

  strings:
    $s1 = "bananaAgent = ((1 | (1 ^ 0)), this);" fullword ascii
    $s2 = "duplicateLexicon[(\"\\u0073e\" + \"\\u0070a\" + \"\\u0072\\u0061\" + \"t\\u0069o\\u006e\", function String.prototype.bankResiden" ascii
    $s3 = "while(duplicateLexicon[(\"\\u0073h\\u006frt\\u0073\", \"\\u0062o\\u0073\\u0073\", \"c\\u0061\" + \"\\u006c\\u0065\\u006e\\u0064" ascii
    $s4 = "while(duplicateLexicon[(\"\\u0073h\\u006frt\\u0073\", \"\\u0062o\\u0073\\u0073\", \"c\\u0061\" + \"\\u006c\\u0065\\u006e\\u0064" ascii
    $s5 = "} catch(relaxationSymmetry) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}