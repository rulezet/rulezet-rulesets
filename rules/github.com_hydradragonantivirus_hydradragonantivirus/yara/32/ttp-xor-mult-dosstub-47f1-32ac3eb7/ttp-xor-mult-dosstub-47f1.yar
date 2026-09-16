rule TTP_XOR_MULT_DOSStub_47f1 {
  strings:
    $key_47f1 = { 13 99 [2] 67 81 [2] 20 83 [2] 67 92 [2] 29 9e [2] 25 94 [2] 32 9f [2] 29 d1 [2] 14 }

  condition:
    any of them
}