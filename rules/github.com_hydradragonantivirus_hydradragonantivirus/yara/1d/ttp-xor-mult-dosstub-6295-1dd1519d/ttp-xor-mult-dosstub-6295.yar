rule TTP_XOR_MULT_DOSStub_6295 {
  strings:
    $key_6295 = { 36 fd [2] 42 e5 [2] 05 e7 [2] 42 f6 [2] 0c fa [2] 00 f0 [2] 17 fb [2] 0c b5 [2] 31 }

  condition:
    any of them
}