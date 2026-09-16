rule TTP_XOR_MULT_DOSStub_0336 {
  strings:
    $key_0336 = { 57 5e [2] 23 46 [2] 64 44 [2] 23 55 [2] 6d 59 [2] 61 53 [2] 76 58 [2] 6d 16 [2] 50 }

  condition:
    any of them
}