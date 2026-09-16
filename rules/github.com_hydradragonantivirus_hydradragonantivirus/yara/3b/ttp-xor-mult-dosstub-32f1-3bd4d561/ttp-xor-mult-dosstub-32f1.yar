rule TTP_XOR_MULT_DOSStub_32f1 {
  strings:
    $key_32f1 = { 66 99 [2] 12 81 [2] 55 83 [2] 12 92 [2] 5c 9e [2] 50 94 [2] 47 9f [2] 5c d1 [2] 61 }

  condition:
    any of them
}