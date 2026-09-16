rule TTP_XOR_MULT_DOSStub_7542 {
  strings:
    $key_7542 = { 21 2a [2] 55 32 [2] 12 30 [2] 55 21 [2] 1b 2d [2] 17 27 [2] 00 2c [2] 1b 62 [2] 26 }

  condition:
    any of them
}