rule TTP_XOR_MULT_DOSStub_b6f1 {
  strings:
    $key_b6f1 = { e2 99 [2] 96 81 [2] d1 83 [2] 96 92 [2] d8 9e [2] d4 94 [2] c3 9f [2] d8 d1 [2] e5 }

  condition:
    any of them
}