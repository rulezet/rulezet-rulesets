rule TTP_XOR_MULT_DOSStub_0542 {
  strings:
    $key_0542 = { 51 2a [2] 25 32 [2] 62 30 [2] 25 21 [2] 6b 2d [2] 67 27 [2] 70 2c [2] 6b 62 [2] 56 }

  condition:
    any of them
}