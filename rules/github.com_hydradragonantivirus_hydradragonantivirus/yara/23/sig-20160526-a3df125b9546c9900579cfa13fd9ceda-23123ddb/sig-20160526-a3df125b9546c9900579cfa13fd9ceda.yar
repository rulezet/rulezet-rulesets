rule sig_20160526_a3df125b9546c9900579cfa13fd9ceda {
  meta:
    description = "datamaliciousorder - file 20160526_a3df125b9546c9900579cfa13fd9ceda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecc4a8a96051513fb792c367393d19a447d64b6e81b9e81c4efebaefadb778f5"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]wI" ascii
    $s2 = "rav\\n\\r;\"esr\" = lWUIAZI rav\\n\\r;\"t\" = 0gMZD rav;};5uNNTINF nruter{)5uNNTINF(1kSJC noitcnuf\\n\\r;\"nepo\" = oAST rav\\n" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}