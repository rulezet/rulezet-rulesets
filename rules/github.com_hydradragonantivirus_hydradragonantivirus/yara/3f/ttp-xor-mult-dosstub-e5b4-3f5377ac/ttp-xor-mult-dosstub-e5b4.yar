rule TTP_XOR_MULT_DOSStub_e5b4 {
  strings:
    $key_e5b4 = { b1 dc [2] c5 c4 [2] 82 c6 [2] c5 d7 [2] 8b db [2] 87 d1 [2] 90 da [2] 8b 94 [2] b6 }

  condition:
    any of them
}