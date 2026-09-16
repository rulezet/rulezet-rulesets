rule TTP_XOR_MULT_DOSStub_0c2b {
  strings:
    $key_0c2b = { 58 43 [2] 2c 5b [2] 6b 59 [2] 2c 48 [2] 62 44 [2] 6e 4e [2] 79 45 [2] 62 0b [2] 5f }

  condition:
    any of them
}