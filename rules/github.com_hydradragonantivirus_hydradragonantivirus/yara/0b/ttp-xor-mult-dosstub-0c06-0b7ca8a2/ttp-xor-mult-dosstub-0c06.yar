rule TTP_XOR_MULT_DOSStub_0c06 {
  strings:
    $key_0c06 = { 58 6e [2] 2c 76 [2] 6b 74 [2] 2c 65 [2] 62 69 [2] 6e 63 [2] 79 68 [2] 62 26 [2] 5f }

  condition:
    any of them
}