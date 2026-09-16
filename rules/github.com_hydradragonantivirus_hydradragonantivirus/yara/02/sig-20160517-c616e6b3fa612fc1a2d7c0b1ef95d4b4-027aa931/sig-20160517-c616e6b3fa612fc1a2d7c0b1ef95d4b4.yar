rule sig_20160517_c616e6b3fa612fc1a2d7c0b1ef95d4b4 {
  meta:
    description = "datamaliciousorder - file 20160517_c616e6b3fa612fc1a2d7c0b1ef95d4b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15f525f1e0de56558583515f0af21f362821f44ca9bedfa00ccd26ea393bbe9a"

  strings:
    $s1 = "var ba2xvp='vjdpa2apd4mfrag42u vtfqnqpql1bgssn2bkmujgyinrcodblcopefqq2shbgm2anwnrfvtwnmnyxvwior2=oddkw\\'yxnoptucc1hcwd344noopjm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}