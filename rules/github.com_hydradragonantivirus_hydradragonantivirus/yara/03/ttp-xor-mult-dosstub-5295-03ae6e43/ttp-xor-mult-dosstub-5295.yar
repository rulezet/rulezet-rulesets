rule TTP_XOR_MULT_DOSStub_5295 {
  strings:
    $key_5295 = { 06 fd [2] 72 e5 [2] 35 e7 [2] 72 f6 [2] 3c fa [2] 30 f0 [2] 27 fb [2] 3c b5 [2] 01 }

  condition:
    any of them
}