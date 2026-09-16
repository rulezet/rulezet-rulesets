rule TTP_XOR_MULT_DOSStub_b5f1 {
  strings:
    $key_b5f1 = { e1 99 [2] 95 81 [2] d2 83 [2] 95 92 [2] db 9e [2] d7 94 [2] c0 9f [2] db d1 [2] e6 }

  condition:
    any of them
}