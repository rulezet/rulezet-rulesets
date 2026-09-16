rule sig_20161024_9049ca76d7a55143cafa31c7bb78d195 {
  meta:
    description = "datamaliciousorder - file 20161024_9049ca76d7a55143cafa31c7bb78d195.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9429d3a101f4462499fc6607edcf72267df6a895260d65f53e0edaa7447c3f19"

  strings:
    $s1 = "} while (aw++ < io);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}