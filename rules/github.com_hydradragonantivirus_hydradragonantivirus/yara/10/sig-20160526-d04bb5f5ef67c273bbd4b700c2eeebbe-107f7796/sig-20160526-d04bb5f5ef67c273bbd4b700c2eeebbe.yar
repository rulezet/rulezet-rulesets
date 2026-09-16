rule sig_20160526_d04bb5f5ef67c273bbd4b700c2eeebbe {
  meta:
    description = "datamaliciousorder - file 20160526_d04bb5f5ef67c273bbd4b700c2eeebbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94214667d2ce16af1aad714f53b6690617c02b6aff6ebe2e90c0291433638631"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "HURL rav\\n\\r;\"htg\" = 2hDMX rav\\n\\r;\"Cmorf\" = 4aRVWRIO rav\\n\\r;\"rah\" = dQOJ rav\\n\\r;\"edoC\" = lXLE rav\\n\\r;\"ioj" ascii
    $s3 = "i\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wF" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}