rule TTP_XOR_MULT_DOSStub_0c5d {
  strings:
    $key_0c5d = { 58 35 [2] 2c 2d [2] 6b 2f [2] 2c 3e [2] 62 32 [2] 6e 38 [2] 79 33 [2] 62 7d [2] 5f }

  condition:
    any of them
}