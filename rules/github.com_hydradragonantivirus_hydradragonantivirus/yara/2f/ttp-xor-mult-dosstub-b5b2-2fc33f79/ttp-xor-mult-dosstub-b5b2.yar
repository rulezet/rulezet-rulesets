rule TTP_XOR_MULT_DOSStub_b5b2 {
  strings:
    $key_b5b2 = { e1 da [2] 95 c2 [2] d2 c0 [2] 95 d1 [2] db dd [2] d7 d7 [2] c0 dc [2] db 92 [2] e6 }

  condition:
    any of them
}