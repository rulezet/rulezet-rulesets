rule TTP_XOR_MULT_DOSStub_e2f1 {
  strings:
    $key_e2f1 = { b6 99 [2] c2 81 [2] 85 83 [2] c2 92 [2] 8c 9e [2] 80 94 [2] 97 9f [2] 8c d1 [2] b1 }

  condition:
    any of them
}