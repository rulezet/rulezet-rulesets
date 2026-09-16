rule TTP_XOR_MULT_DOSStub_a0c8 {
  strings:
    $key_a0c8 = { f4 a0 [2] 80 b8 [2] c7 ba [2] 80 ab [2] ce a7 [2] c2 ad [2] d5 a6 [2] ce e8 [2] f3 }

  condition:
    any of them
}