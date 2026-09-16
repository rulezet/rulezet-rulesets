rule sig_20160526_adcb0e059d1b95693ee8373f06b79d0b {
  meta:
    description = "datamaliciousorder - file 20160526_adcb0e059d1b95693ee8373f06b79d0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de1526dfd2d378b8df5af89a5fa9a267cd8aae166b9a15ac773efc721a3fe449"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\"" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}