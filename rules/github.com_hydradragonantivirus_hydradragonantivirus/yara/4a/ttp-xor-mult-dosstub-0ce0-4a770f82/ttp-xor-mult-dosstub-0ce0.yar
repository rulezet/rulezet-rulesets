rule TTP_XOR_MULT_DOSStub_0ce0 {
  strings:
    $key_0ce0 = { 58 88 [2] 2c 90 [2] 6b 92 [2] 2c 83 [2] 62 8f [2] 6e 85 [2] 79 8e [2] 62 c0 [2] 5f }

  condition:
    any of them
}