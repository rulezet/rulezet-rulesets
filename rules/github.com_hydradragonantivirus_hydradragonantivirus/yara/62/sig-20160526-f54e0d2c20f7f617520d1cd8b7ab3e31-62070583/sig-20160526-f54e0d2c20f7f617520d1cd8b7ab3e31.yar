rule sig_20160526_f54e0d2c20f7f617520d1cd8b7ab3e31 {
  meta:
    description = "datamaliciousorder - file 20160526_f54e0d2c20f7f617520d1cd8b7ab3e31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8b09b0d6df276f937885453988c022f1096612e4d60ac4829982e0e53754bca"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(iZOGKXQ noitcnuf\\n\\r;\"iso" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}