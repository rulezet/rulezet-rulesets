rule TTP_XOR_MULT_DOSStub_6495 {
  strings:
    $key_6495 = { 30 fd [2] 44 e5 [2] 03 e7 [2] 44 f6 [2] 0a fa [2] 06 f0 [2] 11 fb [2] 0a b5 [2] 37 }

  condition:
    any of them
}