rule TTP_XOR_MULT_DOSStub_1b42 {
  strings:
    $key_1b42 = { 4f 2a [2] 3b 32 [2] 7c 30 [2] 3b 21 [2] 75 2d [2] 79 27 [2] 6e 2c [2] 75 62 [2] 48 }

  condition:
    any of them
}