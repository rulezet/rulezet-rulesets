rule TTP_XOR_MULT_DOSStub_3295 {
  strings:
    $key_3295 = { 66 fd [2] 12 e5 [2] 55 e7 [2] 12 f6 [2] 5c fa [2] 50 f0 [2] 47 fb [2] 5c b5 [2] 61 }

  condition:
    any of them
}