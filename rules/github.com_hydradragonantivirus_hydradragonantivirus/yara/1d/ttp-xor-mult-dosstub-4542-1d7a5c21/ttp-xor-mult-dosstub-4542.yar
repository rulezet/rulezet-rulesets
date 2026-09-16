rule TTP_XOR_MULT_DOSStub_4542 {
  strings:
    $key_4542 = { 11 2a [2] 65 32 [2] 22 30 [2] 65 21 [2] 2b 2d [2] 27 27 [2] 30 2c [2] 2b 62 [2] 16 }

  condition:
    any of them
}