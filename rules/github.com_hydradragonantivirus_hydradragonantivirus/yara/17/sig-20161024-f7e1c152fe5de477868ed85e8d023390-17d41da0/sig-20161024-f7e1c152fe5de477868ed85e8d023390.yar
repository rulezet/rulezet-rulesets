rule sig_20161024_f7e1c152fe5de477868ed85e8d023390 {
  meta:
    description = "datamaliciousorder - file 20161024_f7e1c152fe5de477868ed85e8d023390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59130be37a2d2041c75f4d4ee58d0d44d7aab7f9ce1162612b39da7bf1593304"

  strings:
    $s1 = "} while (xr++ < zn0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}