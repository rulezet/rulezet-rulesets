rule TTP_XOR_MULT_DOSStub_0c3b {
  strings:
    $key_0c3b = { 58 53 [2] 2c 4b [2] 6b 49 [2] 2c 58 [2] 62 54 [2] 6e 5e [2] 79 55 [2] 62 1b [2] 5f }

  condition:
    any of them
}