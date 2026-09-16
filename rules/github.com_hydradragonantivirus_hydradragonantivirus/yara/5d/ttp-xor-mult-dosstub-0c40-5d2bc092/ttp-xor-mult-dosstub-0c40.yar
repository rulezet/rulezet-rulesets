rule TTP_XOR_MULT_DOSStub_0c40 {
  strings:
    $key_0c40 = { 58 28 [2] 2c 30 [2] 6b 32 [2] 2c 23 [2] 62 2f [2] 6e 25 [2] 79 2e [2] 62 60 [2] 5f }

  condition:
    any of them
}