rule TTP_XOR_MULT_DOSStub_5544 {
  strings:
    $key_5544 = { 01 2c [2] 75 34 [2] 32 36 [2] 75 27 [2] 3b 2b [2] 37 21 [2] 20 2a [2] 3b 64 [2] 06 }

  condition:
    any of them
}