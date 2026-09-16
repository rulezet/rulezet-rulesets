rule TTP_XOR_MULT_DOSStub_0c59 {
  strings:
    $key_0c59 = { 58 31 [2] 2c 29 [2] 6b 2b [2] 2c 3a [2] 62 36 [2] 6e 3c [2] 79 37 [2] 62 79 [2] 5f }

  condition:
    any of them
}