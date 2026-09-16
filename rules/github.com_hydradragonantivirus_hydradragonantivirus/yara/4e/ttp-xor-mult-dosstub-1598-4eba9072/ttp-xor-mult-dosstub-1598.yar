rule TTP_XOR_MULT_DOSStub_1598 {
  strings:
    $key_1598 = { 41 f0 [2] 35 e8 [2] 72 ea [2] 35 fb [2] 7b f7 [2] 77 fd [2] 60 f6 [2] 7b b8 [2] 46 }

  condition:
    any of them
}