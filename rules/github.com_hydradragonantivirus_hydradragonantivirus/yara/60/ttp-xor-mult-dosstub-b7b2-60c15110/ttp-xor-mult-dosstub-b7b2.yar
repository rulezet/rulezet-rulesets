rule TTP_XOR_MULT_DOSStub_b7b2 {
  strings:
    $key_b7b2 = { e3 da [2] 97 c2 [2] d0 c0 [2] 97 d1 [2] d9 dd [2] d5 d7 [2] c2 dc [2] d9 92 [2] e4 }

  condition:
    any of them
}