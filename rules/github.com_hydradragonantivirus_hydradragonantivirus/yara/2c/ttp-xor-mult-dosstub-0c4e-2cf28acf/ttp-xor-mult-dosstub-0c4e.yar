rule TTP_XOR_MULT_DOSStub_0c4e {
  strings:
    $key_0c4e = { 58 26 [2] 2c 3e [2] 6b 3c [2] 2c 2d [2] 62 21 [2] 6e 2b [2] 79 20 [2] 62 6e [2] 5f }

  condition:
    any of them
}