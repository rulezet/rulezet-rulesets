rule TTP_XOR_MULT_DOSStub_0c55 {
  strings:
    $key_0c55 = { 58 3d [2] 2c 25 [2] 6b 27 [2] 2c 36 [2] 62 3a [2] 6e 30 [2] 79 3b [2] 62 75 [2] 5f }

  condition:
    any of them
}