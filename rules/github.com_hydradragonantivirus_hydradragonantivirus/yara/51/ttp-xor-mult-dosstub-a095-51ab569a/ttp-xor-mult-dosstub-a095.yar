rule TTP_XOR_MULT_DOSStub_a095 {
  strings:
    $key_a095 = { f4 fd [2] 80 e5 [2] c7 e7 [2] 80 f6 [2] ce fa [2] c2 f0 [2] d5 fb [2] ce b5 [2] f3 }

  condition:
    any of them
}