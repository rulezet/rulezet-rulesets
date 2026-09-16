rule TTP_XOR_MULT_DOSStub_1cf1 {
  strings:
    $key_1cf1 = { 48 99 [2] 3c 81 [2] 7b 83 [2] 3c 92 [2] 72 9e [2] 7e 94 [2] 69 9f [2] 72 d1 [2] 4f }

  condition:
    any of them
}