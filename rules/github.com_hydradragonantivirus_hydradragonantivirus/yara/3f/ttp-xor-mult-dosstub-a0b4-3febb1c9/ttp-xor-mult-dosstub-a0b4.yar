rule TTP_XOR_MULT_DOSStub_a0b4 {
  strings:
    $key_a0b4 = { f4 dc [2] 80 c4 [2] c7 c6 [2] 80 d7 [2] ce db [2] c2 d1 [2] d5 da [2] ce 94 [2] f3 }

  condition:
    any of them
}