rule TTP_XOR_MULT_DOSStub_0c50 {
  strings:
    $key_0c50 = { 58 38 [2] 2c 20 [2] 6b 22 [2] 2c 33 [2] 62 3f [2] 6e 35 [2] 79 3e [2] 62 70 [2] 5f }

  condition:
    any of them
}