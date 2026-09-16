rule _20160526_b4a5548c082b731eb0bdd9ce71b452f4_20160526_b9969da46520_733 {
  meta:
    description = "datamaliciousorder - from files 20160526_b4a5548c082b731eb0bdd9ce71b452f4.js, 20160526_b9969da465200d368a92b9ef18d83e3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4be4a79a46f4930cbd4007da332ecea9539cb5443ee64ae64655a1ce7929541"
    hash2       = "f6ae8f3e7890aa885e8497df18da01cfbe657a31761f11216cfa80ee713dc281"

  strings:
    $s1 = "\\n\\r;)rKIUQYC + )dAYQZTO(hAXGJIP + 5mNTKOZB + )4qKUSOZG(7xHUXEVX + ))(};6tTPO nruter{)(4wMMRBYK noitcnuf((]nNKP + )2gVBUIQD(9q" ascii
    $s2 = "X + 7kHYL + ))(};yERD nruter{)(lGLQ noitcnuf([tpircSW = 5pAOOHGN rav" fullword ascii
    $s3 = "\\n\\r;)(yarrA wen = 4xKCNGBX rav    \\n\\r   {\\n\\r)/*  cYq cVm iAC */ wKIXQBL(0mDUQ noitcnuf\\n\\r\\n\\r\\n\\r;}\\n\\r;)4qGBY" ascii
    $s4 = "EHVB noitcnuf((sgnirtStnemnorivnEdnapxE.wVWSTAW = wXSKJCZ rav\\n\\r;)lGWBJGP + tYXRSDN + 7lRBGQZV(]nNKP + 2gVBUIQD + 7kHYL + yER" ascii
    $s5 = "VBUIQD nruter{)(cVKJ noitcnuf( + )7kHYL(pUJIZAX + ))(};yERD nruter{)(nOYLWNX noitcnuf([tpircSW = 4oHPX rav    \\n\\r{\\n\\r)gDIQ" ascii
    $s6 = "uf\\n\\r;\".o\" = lBHOBZI rav\\n\\r;\"8/ku\" = dHQVKVL rav\\n\\r;\"ot4\" = 7sSZO rav\\n\\r;\"h\" = hPPMOEX rav\\n\\r;\"aerC\" = " ascii

  condition:
    (uint16(0) == 0x2a2f and (all of them)
    ) or (all of them)
}