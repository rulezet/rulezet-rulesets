rule sig_20160525_c1fa4d629ec1457461ea42921badd882 {
  meta:
    description = "datamaliciousorder - file 20160525_c1fa4d629ec1457461ea42921badd882.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5642c959a5cc7a5b4c1e564a86d4af9e07489424709a32def6563adaa942417"

  strings:
    $s1 = "llock rav\\n;\"86x\\\\t\" = mk rav\\n;\"e37x\\\\\" = gedotdark rav\\n;\"46x\\\\n\" = keppelk rav\\n;\"l35x\\\\\" = modnark rav" ascii
    $s2 = "n\\n;)eixodh(gsmh + img + eixoda = modnara rav\\n;rerednerg + cthg + tsilslianbmuhtog + ssorcag + modnar = eixoda rav\\n;)))(};d" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}