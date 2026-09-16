rule TTP_XOR_MULT_DOSStub_3542 {
  strings:
    $key_3542 = { 61 2a [2] 15 32 [2] 52 30 [2] 15 21 [2] 5b 2d [2] 57 27 [2] 40 2c [2] 5b 62 [2] 66 }

  condition:
    any of them
}