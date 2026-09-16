rule TTP_XOR_MULT_DOSStub_6cf1 {
  strings:
    $key_6cf1 = { 38 99 [2] 4c 81 [2] 0b 83 [2] 4c 92 [2] 02 9e [2] 0e 94 [2] 19 9f [2] 02 d1 [2] 3f }

  condition:
    any of them
}