rule TTP_XOR_MULT_DOSStub_0c6d {
  strings:
    $key_0c6d = { 58 05 [2] 2c 1d [2] 6b 1f [2] 2c 0e [2] 62 02 [2] 6e 08 [2] 79 03 [2] 62 4d [2] 5f }

  condition:
    any of them
}