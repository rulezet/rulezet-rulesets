rule sig_20161024_4191fcde9bbd8509075a5cdac9f7e88b {
  meta:
    description = "datamaliciousorder - file 20161024_4191fcde9bbd8509075a5cdac9f7e88b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5efe9db7c136e7bd6d9ded074e4fbdae0543b0f7c4903870befdd14eb3bef83"

  strings:
    $s1 = "} while (ed++ < mf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}