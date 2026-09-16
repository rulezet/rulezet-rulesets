rule TTP_XOR_MULT_DOSStub_22f1 {
  strings:
    $key_22f1 = { 76 99 [2] 02 81 [2] 45 83 [2] 02 92 [2] 4c 9e [2] 40 94 [2] 57 9f [2] 4c d1 [2] 71 }

  condition:
    any of them
}