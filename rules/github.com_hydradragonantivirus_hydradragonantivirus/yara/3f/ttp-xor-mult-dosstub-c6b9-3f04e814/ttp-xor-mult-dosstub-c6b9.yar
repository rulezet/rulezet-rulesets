rule TTP_XOR_MULT_DOSStub_c6b9 {
  strings:
    $key_c6b9 = { 92 d1 [2] e6 c9 [2] a1 cb [2] e6 da [2] a8 d6 [2] a4 dc [2] b3 d7 [2] a8 99 [2] 95 }

  condition:
    any of them
}