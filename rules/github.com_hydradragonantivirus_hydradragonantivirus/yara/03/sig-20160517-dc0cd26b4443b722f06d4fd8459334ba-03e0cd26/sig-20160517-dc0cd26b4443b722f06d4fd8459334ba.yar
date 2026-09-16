rule sig_20160517_dc0cd26b4443b722f06d4fd8459334ba {
  meta:
    description = "datamaliciousorder - file 20160517_dc0cd26b4443b722f06d4fd8459334ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98cd8c19c8d79ced6c140f09321c24c52d81a32dab0f280fe78fd9c5fc96124c"

  strings:
    $s1 = "var ba2xvp='vjdpa2apd4mfrag42u vtfqnqpql1bgssn2bkmujgyinrcodblcopefqq2shbgm2anwnrfvtwnmnyxvwior2=oddkw\\'yxnoptucc1hcwd344noopjm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}