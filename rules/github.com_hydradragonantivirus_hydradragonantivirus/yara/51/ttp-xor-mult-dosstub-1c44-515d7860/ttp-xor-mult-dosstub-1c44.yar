rule TTP_XOR_MULT_DOSStub_1c44 {
  strings:
    $key_1c44 = { 48 2c [2] 3c 34 [2] 7b 36 [2] 3c 27 [2] 72 2b [2] 7e 21 [2] 69 2a [2] 72 64 [2] 4f }

  condition:
    any of them
}