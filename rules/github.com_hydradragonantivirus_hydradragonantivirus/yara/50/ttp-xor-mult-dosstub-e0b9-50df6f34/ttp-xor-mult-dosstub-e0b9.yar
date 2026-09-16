rule TTP_XOR_MULT_DOSStub_e0b9 {
  strings:
    $key_e0b9 = { b4 d1 [2] c0 c9 [2] 87 cb [2] c0 da [2] 8e d6 [2] 82 dc [2] 95 d7 [2] 8e 99 [2] b3 }

  condition:
    any of them
}