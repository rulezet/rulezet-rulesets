rule sig_20160517_67b4224ac286ec1c03a8e4891f4876e7 {
  meta:
    description = "datamaliciousorder - file 20160517_67b4224ac286ec1c03a8e4891f4876e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9852cfbf3d58e3aee169858b9eacef113529d2f361e79c92eb49c29b7ce21c2e"

  strings:
    $s1 = "var nypvfk='vmqel2akhji4rzkeux jqh4yifxwfv3xr3infipdbabqqlt4hmbnxztqxqv1oucylmtvrdwaiytt3z=uipjb\\'i3ggztxuw1qcloxv4nzpvrmiilfso" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}