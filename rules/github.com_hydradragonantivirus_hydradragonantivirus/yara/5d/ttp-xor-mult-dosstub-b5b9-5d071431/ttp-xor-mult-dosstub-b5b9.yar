rule TTP_XOR_MULT_DOSStub_b5b9 {
  strings:
    $key_b5b9 = { e1 d1 [2] 95 c9 [2] d2 cb [2] 95 da [2] db d6 [2] d7 dc [2] c0 d7 [2] db 99 [2] e6 }

  condition:
    any of them
}