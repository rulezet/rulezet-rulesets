rule TTP_XOR_MULT_DOSStub_0c6b {
  strings:
    $key_0c6b = { 58 03 [2] 2c 1b [2] 6b 19 [2] 2c 08 [2] 62 04 [2] 6e 0e [2] 79 05 [2] 62 4b [2] 5f }

  condition:
    any of them
}