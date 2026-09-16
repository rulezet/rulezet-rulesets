rule TTP_XOR_MULT_DOSStub_0c19 {
  strings:
    $key_0c19 = { 58 71 [2] 2c 69 [2] 6b 6b [2] 2c 7a [2] 62 76 [2] 6e 7c [2] 79 77 [2] 62 39 [2] 5f }

  condition:
    any of them
}