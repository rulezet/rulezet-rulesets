rule TTP_XOR_MULT_DOSStub_5042 {
  strings:
    $key_5042 = { 04 2a [2] 70 32 [2] 37 30 [2] 70 21 [2] 3e 2d [2] 32 27 [2] 25 2c [2] 3e 62 [2] 03 }

  condition:
    any of them
}