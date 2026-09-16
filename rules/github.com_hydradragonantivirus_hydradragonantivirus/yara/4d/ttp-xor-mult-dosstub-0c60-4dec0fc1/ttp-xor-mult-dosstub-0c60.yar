rule TTP_XOR_MULT_DOSStub_0c60 {
  strings:
    $key_0c60 = { 58 08 [2] 2c 10 [2] 6b 12 [2] 2c 03 [2] 62 0f [2] 6e 05 [2] 79 0e [2] 62 40 [2] 5f }

  condition:
    any of them
}