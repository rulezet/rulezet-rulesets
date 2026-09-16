rule sig_20160526_750ca644c4db8d1ddf202d9a15241b9c {
  meta:
    description = "datamaliciousorder - file 20160526_750ca644c4db8d1ddf202d9a15241b9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "926b869ce62988a4db2542ce186e4a75028d1c2fac6b27650038609a9376e4e5"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]6w" ascii
    $s2 = "rav;};aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"o" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}