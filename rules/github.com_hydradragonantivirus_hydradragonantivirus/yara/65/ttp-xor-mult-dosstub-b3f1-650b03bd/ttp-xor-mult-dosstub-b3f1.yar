rule TTP_XOR_MULT_DOSStub_b3f1 {
  strings:
    $key_b3f1 = { e7 99 [2] 93 81 [2] d4 83 [2] 93 92 [2] dd 9e [2] d1 94 [2] c6 9f [2] dd d1 [2] e0 }

  condition:
    any of them
}