rule TTP_XOR_MULT_DOSStub_0c33 {
  strings:
    $key_0c33 = { 58 5b [2] 2c 43 [2] 6b 41 [2] 2c 50 [2] 62 5c [2] 6e 56 [2] 79 5d [2] 62 13 [2] 5f }

  condition:
    any of them
}