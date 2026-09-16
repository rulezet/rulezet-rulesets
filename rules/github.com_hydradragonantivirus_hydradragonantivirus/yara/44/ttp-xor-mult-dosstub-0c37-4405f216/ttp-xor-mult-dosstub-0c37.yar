rule TTP_XOR_MULT_DOSStub_0c37 {
  strings:
    $key_0c37 = { 58 5f [2] 2c 47 [2] 6b 45 [2] 2c 54 [2] 62 58 [2] 6e 52 [2] 79 59 [2] 62 17 [2] 5f }

  condition:
    any of them
}