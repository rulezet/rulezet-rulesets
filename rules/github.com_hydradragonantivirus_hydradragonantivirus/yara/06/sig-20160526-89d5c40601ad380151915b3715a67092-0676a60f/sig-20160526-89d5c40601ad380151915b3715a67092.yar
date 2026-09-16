rule sig_20160526_89d5c40601ad380151915b3715a67092 {
  meta:
    description = "datamaliciousorder - file 20160526_89d5c40601ad380151915b3715a67092.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0f1a1708fe39a557192f3cd4a9c3e54d71bdf6559734bc6f64fa5e633d33cbd"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]6w" ascii
    $s2 = "};aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}