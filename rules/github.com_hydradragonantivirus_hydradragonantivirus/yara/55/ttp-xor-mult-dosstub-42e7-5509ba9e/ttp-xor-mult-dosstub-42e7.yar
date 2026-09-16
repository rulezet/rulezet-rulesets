rule TTP_XOR_MULT_DOSStub_42e7 {
  strings:
    $key_42e7 = { 16 8f [2] 62 97 [2] 25 95 [2] 62 84 [2] 2c 88 [2] 20 82 [2] 37 89 [2] 2c c7 [2] 11 }

  condition:
    any of them
}