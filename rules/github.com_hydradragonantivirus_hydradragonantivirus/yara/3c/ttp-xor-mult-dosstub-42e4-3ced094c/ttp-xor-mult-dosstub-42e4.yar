rule TTP_XOR_MULT_DOSStub_42e4 {
  strings:
    $key_42e4 = { 16 8c [2] 62 94 [2] 25 96 [2] 62 87 [2] 2c 8b [2] 20 81 [2] 37 8a [2] 2c c4 [2] 11 }

  condition:
    any of them
}