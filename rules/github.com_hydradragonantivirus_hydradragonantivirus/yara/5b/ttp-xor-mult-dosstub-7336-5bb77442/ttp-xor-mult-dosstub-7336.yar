rule TTP_XOR_MULT_DOSStub_7336 {
  strings:
    $key_7336 = { 27 5e [2] 53 46 [2] 14 44 [2] 53 55 [2] 1d 59 [2] 11 53 [2] 06 58 [2] 1d 16 [2] 20 }

  condition:
    any of them
}