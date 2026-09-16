rule TTP_XOR_MULT_DOSStub_e0f0 {
  strings:
    $key_e0f0 = { b4 98 [2] c0 80 [2] 87 82 [2] c0 93 [2] 8e 9f [2] 82 95 [2] 95 9e [2] 8e d0 [2] b3 }

  condition:
    any of them
}