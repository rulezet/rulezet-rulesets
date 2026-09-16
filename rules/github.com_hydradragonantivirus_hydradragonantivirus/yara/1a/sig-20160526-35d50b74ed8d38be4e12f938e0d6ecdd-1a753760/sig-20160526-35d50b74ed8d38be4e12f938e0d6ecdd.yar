rule sig_20160526_35d50b74ed8d38be4e12f938e0d6ecdd {
  meta:
    description = "datamaliciousorder - file 20160526_35d50b74ed8d38be4e12f938e0d6ecdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d1381717b7047070e0f1a077049e7b2a167ba062915a5ad5891313daa6ccc74"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFE" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}