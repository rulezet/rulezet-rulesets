rule TTP_XOR_MULT_DOSStub_2c58 {
  strings:
    $key_2c58 = { 78 30 [2] 0c 28 [2] 4b 2a [2] 0c 3b [2] 42 37 [2] 4e 3d [2] 59 36 [2] 42 78 [2] 7f }

  condition:
    any of them
}