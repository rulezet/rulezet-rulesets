rule TTP_XOR_MULT_DOSStub_0c02 {
  strings:
    $key_0c02 = { 58 6a [2] 2c 72 [2] 6b 70 [2] 2c 61 [2] 62 6d [2] 6e 67 [2] 79 6c [2] 62 22 [2] 5f }

  condition:
    any of them
}