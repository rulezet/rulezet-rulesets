rule sig_20161024_f5af8c206e87d0481e96f9e0fb3203ea {
  meta:
    description = "datamaliciousorder - file 20161024_f5af8c206e87d0481e96f9e0fb3203ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "482007aa5c5e9a90f989294ed1714463fcbeb46fdd31c85a3d8b30c3238d8cb2"

  strings:
    $s1 = "} while (jd0++ < io);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}