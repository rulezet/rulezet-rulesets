rule TTP_XOR_MULT_DOSStub_0c76 {
  strings:
    $key_0c76 = { 58 1e [2] 2c 06 [2] 6b 04 [2] 2c 15 [2] 62 19 [2] 6e 13 [2] 79 18 [2] 62 56 [2] 5f }

  condition:
    any of them
}