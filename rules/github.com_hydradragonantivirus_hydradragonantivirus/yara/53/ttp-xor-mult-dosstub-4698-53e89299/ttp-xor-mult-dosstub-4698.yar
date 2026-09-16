rule TTP_XOR_MULT_DOSStub_4698 {
  strings:
    $key_4698 = { 12 f0 [2] 66 e8 [2] 21 ea [2] 66 fb [2] 28 f7 [2] 24 fd [2] 33 f6 [2] 28 b8 [2] 15 }

  condition:
    any of them
}