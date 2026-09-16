rule TTP_XOR_MULT_DOSStub_6c44 {
  strings:
    $key_6c44 = { 38 2c [2] 4c 34 [2] 0b 36 [2] 4c 27 [2] 02 2b [2] 0e 21 [2] 19 2a [2] 02 64 [2] 3f }

  condition:
    any of them
}