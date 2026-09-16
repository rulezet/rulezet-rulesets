rule TTP_XOR_MULT_DOSStub_2542 {
  strings:
    $key_2542 = { 71 2a [2] 05 32 [2] 42 30 [2] 05 21 [2] 4b 2d [2] 47 27 [2] 50 2c [2] 4b 62 [2] 76 }

  condition:
    any of them
}