rule TTP_XOR_MULT_DOSStub_e2b9 {
  strings:
    $key_e2b9 = { b6 d1 [2] c2 c9 [2] 85 cb [2] c2 da [2] 8c d6 [2] 80 dc [2] 97 d7 [2] 8c 99 [2] b1 }

  condition:
    any of them
}