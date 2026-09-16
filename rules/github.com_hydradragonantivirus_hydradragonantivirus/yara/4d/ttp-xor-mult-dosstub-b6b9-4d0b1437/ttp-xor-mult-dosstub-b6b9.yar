rule TTP_XOR_MULT_DOSStub_b6b9 {
  strings:
    $key_b6b9 = { e2 d1 [2] 96 c9 [2] d1 cb [2] 96 da [2] d8 d6 [2] d4 dc [2] c3 d7 [2] d8 99 [2] e5 }

  condition:
    any of them
}