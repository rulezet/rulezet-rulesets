rule TTP_XOR_MULT_DOSStub_42e2 {
  strings:
    $key_42e2 = { 16 8a [2] 62 92 [2] 25 90 [2] 62 81 [2] 2c 8d [2] 20 87 [2] 37 8c [2] 2c c2 [2] 11 }

  condition:
    any of them
}