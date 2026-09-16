rule TTP_XOR_MULT_DOSStub_41f1 {
  strings:
    $key_41f1 = { 15 99 [2] 61 81 [2] 26 83 [2] 61 92 [2] 2f 9e [2] 23 94 [2] 34 9f [2] 2f d1 [2] 12 }

  condition:
    any of them
}