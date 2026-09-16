rule TTP_XOR_MULT_DOSStub_0c53 {
  strings:
    $key_0c53 = { 58 3b [2] 2c 23 [2] 6b 21 [2] 2c 30 [2] 62 3c [2] 6e 36 [2] 79 3d [2] 62 73 [2] 5f }

  condition:
    any of them
}