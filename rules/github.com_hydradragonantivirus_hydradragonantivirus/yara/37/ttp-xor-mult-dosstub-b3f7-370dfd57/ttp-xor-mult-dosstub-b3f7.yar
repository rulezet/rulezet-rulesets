rule TTP_XOR_MULT_DOSStub_b3f7 {
  strings:
    $key_b3f7 = { e7 9f [2] 93 87 [2] d4 85 [2] 93 94 [2] dd 98 [2] d1 92 [2] c6 99 [2] dd d7 [2] e0 }

  condition:
    any of them
}