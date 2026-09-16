rule sig_20160526_721b5276145d2fb7b7e0d8db4abc6bb0 {
  meta:
    description = "datamaliciousorder - file 20160526_721b5276145d2fb7b7e0d8db4abc6bb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "badaecb272a1ac23877dfe3a9eb6bbf489761e9b2a1de10a8c248e841aa392de"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]6w" ascii
    $s2 = "};aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}