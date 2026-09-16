rule TTP_XOR_MULT_DOSStub_b3b4 {
  strings:
    $key_b3b4 = { e7 dc [2] 93 c4 [2] d4 c6 [2] 93 d7 [2] dd db [2] d1 d1 [2] c6 da [2] dd 94 [2] e0 }

  condition:
    any of them
}