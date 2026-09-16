rule sig_20160525_e8cbd01ccc544004c05fba1e098d3bc3 {
  meta:
    description = "datamaliciousorder - file 20160525_e8cbd01ccc544004c05fba1e098d3bc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d3fa4098fe2b25e163581482508de13f79b5335979e4fc33a3afe1cb77c7d84"

  strings:
    $s1 = " + suidarelcitrapg + gsmg + modnar = eixoda rav\\n;)eixodg + imf(sgnirtStnemnorivnEdnapxE.dnenoisillocb = modnar rav\\n;)))(};de" ascii
    $s2 = " = eixodj rav;};keppelj nruter{)keppelj(gedotdarj noitcnuf;};mj nruter{)mj(dnenoisillocj noitcnuf;};suidarelcitrapj nruter{)suid" ascii
    $s3 = "traps nruter{)(gedotdars noitcnuf([eixodb    \\n;)(])eixodj(gsmj + imi[eixodb    \\n;mb = ]rerednern + cthn[eixodb    \\n;tsilsl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}