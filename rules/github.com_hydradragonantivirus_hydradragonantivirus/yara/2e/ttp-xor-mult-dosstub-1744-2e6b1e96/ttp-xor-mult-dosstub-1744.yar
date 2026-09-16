rule TTP_XOR_MULT_DOSStub_1744 {
  strings:
    $key_1744 = { 43 2c [2] 37 34 [2] 70 36 [2] 37 27 [2] 79 2b [2] 75 21 [2] 62 2a [2] 79 64 [2] 44 }

  condition:
    any of them
}