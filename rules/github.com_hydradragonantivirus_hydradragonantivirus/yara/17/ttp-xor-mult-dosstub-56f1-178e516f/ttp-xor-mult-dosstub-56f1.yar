rule TTP_XOR_MULT_DOSStub_56f1 {
  strings:
    $key_56f1 = { 02 99 [2] 76 81 [2] 31 83 [2] 76 92 [2] 38 9e [2] 34 94 [2] 23 9f [2] 38 d1 [2] 05 }

  condition:
    any of them
}