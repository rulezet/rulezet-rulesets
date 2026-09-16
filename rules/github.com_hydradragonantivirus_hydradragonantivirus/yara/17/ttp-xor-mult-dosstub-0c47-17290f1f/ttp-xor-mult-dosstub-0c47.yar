rule TTP_XOR_MULT_DOSStub_0c47 {
  strings:
    $key_0c47 = { 58 2f [2] 2c 37 [2] 6b 35 [2] 2c 24 [2] 62 28 [2] 6e 22 [2] 79 29 [2] 62 67 [2] 5f }

  condition:
    any of them
}