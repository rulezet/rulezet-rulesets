rule TTP_XOR_MULT_DOSStub_0c39 {
  strings:
    $key_0c39 = { 58 51 [2] 2c 49 [2] 6b 4b [2] 2c 5a [2] 62 56 [2] 6e 5c [2] 79 57 [2] 62 19 [2] 5f }

  condition:
    any of them
}