rule TTP_XOR_MULT_DOSStub_17f1 {
  strings:
    $key_17f1 = { 43 99 [2] 37 81 [2] 70 83 [2] 37 92 [2] 79 9e [2] 75 94 [2] 62 9f [2] 79 d1 [2] 44 }

  condition:
    any of them
}