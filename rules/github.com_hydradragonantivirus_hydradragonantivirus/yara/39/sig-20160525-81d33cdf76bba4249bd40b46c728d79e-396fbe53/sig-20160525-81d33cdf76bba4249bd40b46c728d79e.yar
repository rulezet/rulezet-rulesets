rule sig_20160525_81d33cdf76bba4249bd40b46c728d79e {
  meta:
    description = "datamaliciousorder - file 20160525_81d33cdf76bba4249bd40b46c728d79e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74b7937b3b9da0a9a8d1983045ad2d1b95f8e36df4e30676d72e8f178a5d8e09"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}