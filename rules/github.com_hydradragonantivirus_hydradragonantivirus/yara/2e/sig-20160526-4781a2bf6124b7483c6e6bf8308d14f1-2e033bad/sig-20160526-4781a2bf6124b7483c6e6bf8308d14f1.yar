rule sig_20160526_4781a2bf6124b7483c6e6bf8308d14f1 {
  meta:
    description = "datamaliciousorder - file 20160526_4781a2bf6124b7483c6e6bf8308d14f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03a93963e58f214abc9eebe29af6968a96d3ed419c9c3fec60832ae4e48bde03"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]cT" ascii
    $s2 = "\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFE" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}