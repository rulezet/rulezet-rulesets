rule TTP_XOR_MULT_DOSStub_0c1d {
  strings:
    $key_0c1d = { 58 75 [2] 2c 6d [2] 6b 6f [2] 2c 7e [2] 62 72 [2] 6e 78 [2] 79 73 [2] 62 3d [2] 5f }

  condition:
    any of them
}