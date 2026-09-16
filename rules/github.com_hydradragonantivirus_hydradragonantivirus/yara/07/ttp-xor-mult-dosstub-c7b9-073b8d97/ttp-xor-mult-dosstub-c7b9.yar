rule TTP_XOR_MULT_DOSStub_c7b9 {
  strings:
    $key_c7b9 = { 93 d1 [2] e7 c9 [2] a0 cb [2] e7 da [2] a9 d6 [2] a5 dc [2] b2 d7 [2] a9 99 [2] 94 }

  condition:
    any of them
}