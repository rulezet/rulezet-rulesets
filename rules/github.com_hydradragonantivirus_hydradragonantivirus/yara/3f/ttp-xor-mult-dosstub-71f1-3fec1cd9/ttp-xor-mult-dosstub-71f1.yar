rule TTP_XOR_MULT_DOSStub_71f1 {
  strings:
    $key_71f1 = { 25 99 [2] 51 81 [2] 16 83 [2] 51 92 [2] 1f 9e [2] 13 94 [2] 04 9f [2] 1f d1 [2] 22 }

  condition:
    any of them
}