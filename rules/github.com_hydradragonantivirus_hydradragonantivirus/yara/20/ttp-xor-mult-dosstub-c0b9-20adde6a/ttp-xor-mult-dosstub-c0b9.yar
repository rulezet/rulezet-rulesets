rule TTP_XOR_MULT_DOSStub_c0b9 {
  strings:
    $key_c0b9 = { 94 d1 [2] e0 c9 [2] a7 cb [2] e0 da [2] ae d6 [2] a2 dc [2] b5 d7 [2] ae 99 [2] 93 }

  condition:
    any of them
}