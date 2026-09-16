rule TTP_XOR_MULT_DOSStub_1c72 {
  strings:
    $key_1c72 = { 48 1a [2] 3c 02 [2] 7b 00 [2] 3c 11 [2] 72 1d [2] 7e 17 [2] 69 1c [2] 72 52 [2] 4f }

  condition:
    any of them
}