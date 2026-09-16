rule TTP_XOR_MULT_DOSStub_f4b9 {
  strings:
    $key_f4b9 = { a0 d1 [2] d4 c9 [2] 93 cb [2] d4 da [2] 9a d6 [2] 96 dc [2] 81 d7 [2] 9a 99 [2] a7 }

  condition:
    any of them
}