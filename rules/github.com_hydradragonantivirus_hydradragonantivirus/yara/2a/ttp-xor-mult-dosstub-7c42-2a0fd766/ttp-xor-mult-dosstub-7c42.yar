rule TTP_XOR_MULT_DOSStub_7c42 {
  strings:
    $key_7c42 = { 28 2a [2] 5c 32 [2] 1b 30 [2] 5c 21 [2] 12 2d [2] 1e 27 [2] 09 2c [2] 12 62 [2] 2f }

  condition:
    any of them
}