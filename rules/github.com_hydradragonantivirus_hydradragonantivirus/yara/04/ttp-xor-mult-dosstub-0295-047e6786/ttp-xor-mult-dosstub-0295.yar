rule TTP_XOR_MULT_DOSStub_0295 {
  strings:
    $key_0295 = { 56 fd [2] 22 e5 [2] 65 e7 [2] 22 f6 [2] 6c fa [2] 60 f0 [2] 77 fb [2] 6c b5 [2] 51 }

  condition:
    any of them
}