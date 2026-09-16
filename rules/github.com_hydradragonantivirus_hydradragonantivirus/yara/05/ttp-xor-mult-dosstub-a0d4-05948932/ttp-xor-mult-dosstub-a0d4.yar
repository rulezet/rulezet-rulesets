rule TTP_XOR_MULT_DOSStub_a0d4 {
  strings:
    $key_a0d4 = { f4 bc [2] 80 a4 [2] c7 a6 [2] 80 b7 [2] ce bb [2] c2 b1 [2] d5 ba [2] ce f4 [2] f3 }

  condition:
    any of them
}