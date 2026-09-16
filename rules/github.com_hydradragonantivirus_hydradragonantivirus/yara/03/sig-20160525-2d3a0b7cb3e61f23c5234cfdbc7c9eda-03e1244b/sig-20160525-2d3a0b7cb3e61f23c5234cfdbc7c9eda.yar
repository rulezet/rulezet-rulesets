rule sig_20160525_2d3a0b7cb3e61f23c5234cfdbc7c9eda {
  meta:
    description = "datamaliciousorder - file 20160525_2d3a0b7cb3e61f23c5234cfdbc7c9eda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ae41e5b5c907093c4217682d171600c3245c3485bcfea6afd6cfa2d63f4e6f3"

  strings:
    $s1 = "nenoisillocm rav\\n;\"56x\\\\\" = mm rav;};keppelm nruter{)keppelm(gedotdarm noitcnuf\\n;\"e6x\\\\56x\\\\l\" = modnarm rav\\n;\"" ascii
    $s2 = "pelf + suidarelcitrapf + ))(};gsmf nruter{)(gedotdarf noitcnuf( + eixodf(]tsilslianbmuhtoe + ssorcae + sdnete + ))(};deerde nrut" ascii
    $s3 = "loca rav" fullword ascii
    $s4 = "erm rav;\"Uqh\" = ssorcam rav\\n;\"tabe2x\\\\\" = imm rav\\n;\"t16x\\\\e27x\\\\C\" = eixodn rav\\n;\"bf4x\\\\e\" = gsmn rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}