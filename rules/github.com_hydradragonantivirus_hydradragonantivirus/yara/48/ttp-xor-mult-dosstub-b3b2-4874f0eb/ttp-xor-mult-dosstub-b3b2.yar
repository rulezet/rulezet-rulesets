rule TTP_XOR_MULT_DOSStub_b3b2 {
  strings:
    $key_b3b2 = { e7 da [2] 93 c2 [2] d4 c0 [2] 93 d1 [2] dd dd [2] d1 d7 [2] c6 dc [2] dd 92 [2] e0 }

  condition:
    any of them
}