rule TTP_XOR_MULT_DOSStub_a895 {
  strings:
    $key_a895 = { fc fd [2] 88 e5 [2] cf e7 [2] 88 f6 [2] c6 fa [2] ca f0 [2] dd fb [2] c6 b5 [2] fb }

  condition:
    any of them
}