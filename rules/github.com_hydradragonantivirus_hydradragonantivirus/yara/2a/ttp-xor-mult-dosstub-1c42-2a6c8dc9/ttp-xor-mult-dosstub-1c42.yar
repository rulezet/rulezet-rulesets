rule TTP_XOR_MULT_DOSStub_1c42 {
  strings:
    $key_1c42 = { 48 2a [2] 3c 32 [2] 7b 30 [2] 3c 21 [2] 72 2d [2] 7e 27 [2] 69 2c [2] 72 62 [2] 4f }

  condition:
    any of them
}