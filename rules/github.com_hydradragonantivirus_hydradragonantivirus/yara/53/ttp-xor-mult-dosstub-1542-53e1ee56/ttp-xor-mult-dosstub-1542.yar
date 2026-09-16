rule TTP_XOR_MULT_DOSStub_1542 {
  strings:
    $key_1542 = { 41 2a [2] 35 32 [2] 72 30 [2] 35 21 [2] 7b 2d [2] 77 27 [2] 60 2c [2] 7b 62 [2] 46 }

  condition:
    any of them
}