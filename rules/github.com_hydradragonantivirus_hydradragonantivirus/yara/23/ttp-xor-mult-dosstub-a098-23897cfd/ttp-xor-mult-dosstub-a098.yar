rule TTP_XOR_MULT_DOSStub_a098 {
  strings:
    $key_a098 = { f4 f0 [2] 80 e8 [2] c7 ea [2] 80 fb [2] ce f7 [2] c2 fd [2] d5 f6 [2] ce b8 [2] f3 }

  condition:
    any of them
}