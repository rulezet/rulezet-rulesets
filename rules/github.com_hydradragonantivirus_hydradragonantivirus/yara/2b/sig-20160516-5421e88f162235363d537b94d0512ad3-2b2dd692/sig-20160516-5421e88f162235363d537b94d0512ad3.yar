rule sig_20160516_5421e88f162235363d537b94d0512ad3 {
  meta:
    description = "datamaliciousorder - file 20160516_5421e88f162235363d537b94d0512ad3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e96b1a3a08fcde30b5fdcabc485aa7c667af30fc1ea871b55dbc943667f0b24e"

  strings:
    $s1 = "var x14xz='vvkfy3ap3m13rt4xqj vi3q2bjshasklqcsbmtwqtuvynwfodfxswoxbo2efbv43kdaduy1nkgkjudmmnv4w=l3udz\\'yjokstdmvz1ckuv3unpcfv2i" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}