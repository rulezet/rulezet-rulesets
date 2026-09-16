rule TTP_XOR_MULT_DOSStub_5436 {
  strings:
    $key_5436 = { 00 5e [2] 74 46 [2] 33 44 [2] 74 55 [2] 3a 59 [2] 36 53 [2] 21 58 [2] 3a 16 [2] 07 }

  condition:
    any of them
}