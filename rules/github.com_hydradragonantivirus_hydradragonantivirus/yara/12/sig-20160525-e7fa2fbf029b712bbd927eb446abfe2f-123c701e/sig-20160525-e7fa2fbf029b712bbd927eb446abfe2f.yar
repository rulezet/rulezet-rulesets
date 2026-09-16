rule sig_20160525_e7fa2fbf029b712bbd927eb446abfe2f {
  meta:
    description = "datamaliciousorder - file 20160525_e7fa2fbf029b712bbd927eb446abfe2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1d957f096b0838429d268a8fedaafce5c72ff6f0964591004347e1667616ac5"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]rerednern + cthn[eixodb    \\n\\n;)2 * 1 ,ssor" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}