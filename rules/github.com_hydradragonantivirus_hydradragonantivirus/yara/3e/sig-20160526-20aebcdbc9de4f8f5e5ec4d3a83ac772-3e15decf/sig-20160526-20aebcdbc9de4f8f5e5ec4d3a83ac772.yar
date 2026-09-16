rule sig_20160526_20aebcdbc9de4f8f5e5ec4d3a83ac772 {
  meta:
    description = "datamaliciousorder - file 20160526_20aebcdbc9de4f8f5e5ec4d3a83ac772.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "903ada9acb98ef2a28f15ea4846b81bb03da1dcaad10dfbbba39638f1a4d68d6"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(iZOGKXQ noitcnuf\\n\\r;\"iso" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}