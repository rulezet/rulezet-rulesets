rule sig_20160525_7037d2f6016af6107cbbd56e847ab1d8 {
  meta:
    description = "datamaliciousorder - file 20160525_7037d2f6016af6107cbbd56e847ab1d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa1fecd3568c36889fac418e343997246d1f7f112519b74200955a1199d4a1b"

  strings:
    $s1 = "rav\\n;\"e37x\\\\\" = dnenoisillock rav\\n;\"46x\\\\n\" = mk rav\\n;\"l35x\\\\\" = keppelk rav\\n;\"56x\\\\56x\\\\\" = ecapsetih" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}