rule TTP_XOR_MULT_DOSStub_0c43 {
  strings:
    $key_0c43 = { 58 2b [2] 2c 33 [2] 6b 31 [2] 2c 20 [2] 62 2c [2] 6e 26 [2] 79 2d [2] 62 63 [2] 5f }

  condition:
    any of them
}