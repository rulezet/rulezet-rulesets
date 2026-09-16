rule TTP_XOR_MULT_DOSStub_e0f6 {
  strings:
    $key_e0f6 = { b4 9e [2] c0 86 [2] 87 84 [2] c0 95 [2] 8e 99 [2] 82 93 [2] 95 98 [2] 8e d6 [2] b3 }

  condition:
    any of them
}