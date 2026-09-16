rule TTP_XOR_MULT_DOSStub_0c7b {
  strings:
    $key_0c7b = { 58 13 [2] 2c 0b [2] 6b 09 [2] 2c 18 [2] 62 14 [2] 6e 1e [2] 79 15 [2] 62 5b [2] 5f }

  condition:
    any of them
}