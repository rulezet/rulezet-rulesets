rule TTP_XOR_MULT_DOSStub_f1b9 {
  strings:
    $key_f1b9 = { a5 d1 [2] d1 c9 [2] 96 cb [2] d1 da [2] 9f d6 [2] 93 dc [2] 84 d7 [2] 9f 99 [2] a2 }

  condition:
    any of them
}