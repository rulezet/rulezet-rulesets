rule TTP_XOR_MULT_DOSStub_f295 {
  strings:
    $key_f295 = { a6 fd [2] d2 e5 [2] 95 e7 [2] d2 f6 [2] 9c fa [2] 90 f0 [2] 87 fb [2] 9c b5 [2] a1 }

  condition:
    any of them
}