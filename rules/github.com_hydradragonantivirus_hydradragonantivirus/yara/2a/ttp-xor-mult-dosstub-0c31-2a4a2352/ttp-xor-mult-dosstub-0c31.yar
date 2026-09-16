rule TTP_XOR_MULT_DOSStub_0c31 {
  strings:
    $key_0c31 = { 58 59 [2] 2c 41 [2] 6b 43 [2] 2c 52 [2] 62 5e [2] 6e 54 [2] 79 5f [2] 62 11 [2] 5f }

  condition:
    any of them
}