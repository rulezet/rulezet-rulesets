rule TTP_XOR_MULT_DOSStub_0c10 {
  strings:
    $key_0c10 = { 58 78 [2] 2c 60 [2] 6b 62 [2] 2c 73 [2] 62 7f [2] 6e 75 [2] 79 7e [2] 62 30 [2] 5f }

  condition:
    any of them
}