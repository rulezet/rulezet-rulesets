rule TTP_XOR_MULT_DOSStub_a0d9 {
  strings:
    $key_a0d9 = { f4 b1 [2] 80 a9 [2] c7 ab [2] 80 ba [2] ce b6 [2] c2 bc [2] d5 b7 [2] ce f9 [2] f3 }

  condition:
    any of them
}