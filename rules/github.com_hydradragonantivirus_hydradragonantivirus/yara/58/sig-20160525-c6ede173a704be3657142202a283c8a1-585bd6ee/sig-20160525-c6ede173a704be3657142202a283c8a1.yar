rule sig_20160525_c6ede173a704be3657142202a283c8a1 {
  meta:
    description = "datamaliciousorder - file 20160525_c6ede173a704be3657142202a283c8a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd1d98c81a5e12c95a93c0aae737a406bbdf2ec828705186f7648cfda24c8445"

  strings:
    $s1 = "dnari[rerednera[rerednera | 8 << ]3-])sdneti(dnenoisillocj + )deerdi(gsmj + )modnari(imi[rerednera[rerednera | ]4-]sdneti + deer" ascii
    $s2 = "xodf+ime + rerednere+cthe + tsilslianbmuhtoe+ssorcae+))(};modnare nruter{)(sdnete noitcnuf( + ))(};ecapsetihwxelfe nruter{)(deer" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}