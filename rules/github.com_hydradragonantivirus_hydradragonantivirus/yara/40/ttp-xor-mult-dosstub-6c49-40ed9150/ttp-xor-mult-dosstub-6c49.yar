rule TTP_XOR_MULT_DOSStub_6c49 {
  strings:
    $key_6c49 = { 38 21 [2] 4c 39 [2] 0b 3b [2] 4c 2a [2] 02 26 [2] 0e 2c [2] 19 27 [2] 02 69 [2] 3f }

  condition:
    any of them
}