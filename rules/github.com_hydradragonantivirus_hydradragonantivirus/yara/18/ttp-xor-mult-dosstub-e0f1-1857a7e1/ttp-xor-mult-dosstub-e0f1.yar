rule TTP_XOR_MULT_DOSStub_e0f1 {
  strings:
    $key_e0f1 = { b4 99 [2] c0 81 [2] 87 83 [2] c0 92 [2] 8e 9e [2] 82 94 [2] 95 9f [2] 8e d1 [2] b3 }

  condition:
    any of them
}