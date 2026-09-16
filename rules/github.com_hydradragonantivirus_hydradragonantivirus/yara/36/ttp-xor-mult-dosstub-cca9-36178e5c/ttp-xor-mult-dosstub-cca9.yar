rule TTP_XOR_MULT_DOSStub_cca9 {
  strings:
    $key_cca9 = { 98 c1 [2] ec d9 [2] ab db [2] ec ca [2] a2 c6 [2] ae cc [2] b9 c7 [2] a2 89 [2] 9f }

  condition:
    any of them
}