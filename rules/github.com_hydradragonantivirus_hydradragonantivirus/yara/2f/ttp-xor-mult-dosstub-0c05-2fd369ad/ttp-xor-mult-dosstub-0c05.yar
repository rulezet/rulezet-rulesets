rule TTP_XOR_MULT_DOSStub_0c05 {
  strings:
    $key_0c05 = { 58 6d [2] 2c 75 [2] 6b 77 [2] 2c 66 [2] 62 6a [2] 6e 60 [2] 79 6b [2] 62 25 [2] 5f }

  condition:
    any of them
}