rule TTP_XOR_MULT_DOSStub_c3b9 {
  strings:
    $key_c3b9 = { 97 d1 [2] e3 c9 [2] a4 cb [2] e3 da [2] ad d6 [2] a1 dc [2] b6 d7 [2] ad 99 [2] 90 }

  condition:
    any of them
}