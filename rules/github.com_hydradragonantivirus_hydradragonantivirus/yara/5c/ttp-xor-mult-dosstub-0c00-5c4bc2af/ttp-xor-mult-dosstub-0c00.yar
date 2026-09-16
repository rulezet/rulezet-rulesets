rule TTP_XOR_MULT_DOSStub_0c00 {
  strings:
    $key_0c00 = { 58 68 [2] 2c 70 [2] 6b 72 [2] 2c 63 [2] 62 6f [2] 6e 65 [2] 79 6e [2] 62 20 [2] 5f }

  condition:
    any of them
}