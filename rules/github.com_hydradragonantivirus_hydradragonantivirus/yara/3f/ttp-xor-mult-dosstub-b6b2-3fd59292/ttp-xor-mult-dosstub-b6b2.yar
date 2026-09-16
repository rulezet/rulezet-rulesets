rule TTP_XOR_MULT_DOSStub_b6b2 {
  strings:
    $key_b6b2 = { e2 da [2] 96 c2 [2] d1 c0 [2] 96 d1 [2] d8 dd [2] d4 d7 [2] c3 dc [2] d8 92 [2] e5 }

  condition:
    any of them
}