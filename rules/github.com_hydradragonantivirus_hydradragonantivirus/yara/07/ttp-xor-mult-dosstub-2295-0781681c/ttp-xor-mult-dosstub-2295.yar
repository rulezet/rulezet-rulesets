rule TTP_XOR_MULT_DOSStub_2295 {
  strings:
    $key_2295 = { 76 fd [2] 02 e5 [2] 45 e7 [2] 02 f6 [2] 4c fa [2] 40 f0 [2] 57 fb [2] 4c b5 [2] 71 }

  condition:
    any of them
}