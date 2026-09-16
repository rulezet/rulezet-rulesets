rule TTP_XOR_MULT_DOSStub_c5b9 {
  strings:
    $key_c5b9 = { 91 d1 [2] e5 c9 [2] a2 cb [2] e5 da [2] ab d6 [2] a7 dc [2] b0 d7 [2] ab 99 [2] 96 }

  condition:
    any of them
}