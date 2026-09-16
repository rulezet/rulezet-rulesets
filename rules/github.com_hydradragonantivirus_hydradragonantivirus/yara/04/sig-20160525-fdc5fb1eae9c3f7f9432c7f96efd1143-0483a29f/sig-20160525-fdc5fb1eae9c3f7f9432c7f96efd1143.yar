rule sig_20160525_fdc5fb1eae9c3f7f9432c7f96efd1143 {
  meta:
    description = "datamaliciousorder - file 20160525_fdc5fb1eae9c3f7f9432c7f96efd1143.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25e3395b6ec40bf7afbbd5b322338fdf1b4a2c6ff8e8f21dd2a6333faaea1e86"

  strings:
    $s1 = "dark(]ime + rerednere + cthe + tsilslianbmuhtoe[tpircSW = eixodb rav    \\n{\\n)rerednera ,ssorcaa(suidarelcitrap noitcnuf\\n\\n" ascii
    $s2 = "f rav\\n;\"c6x\\\\l\" = ecapsetihwxelff rav;};tsilslianbmuhtof nruter{)tsilslianbmuhtof(ssorcaf noitcnuf;};sdnetf nruter{)sdnetf" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}