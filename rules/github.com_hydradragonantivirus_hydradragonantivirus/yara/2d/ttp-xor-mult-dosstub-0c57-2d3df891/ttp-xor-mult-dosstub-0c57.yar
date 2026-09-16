rule TTP_XOR_MULT_DOSStub_0c57 {
  strings:
    $key_0c57 = { 58 3f [2] 2c 27 [2] 6b 25 [2] 2c 34 [2] 62 38 [2] 6e 32 [2] 79 39 [2] 62 77 [2] 5f }

  condition:
    any of them
}