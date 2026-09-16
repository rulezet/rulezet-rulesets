rule TTP_XOR_MULT_DOSStub_d398 {
  strings:
    $key_d398 = { 87 f0 [2] f3 e8 [2] b4 ea [2] f3 fb [2] bd f7 [2] b1 fd [2] a6 f6 [2] bd b8 [2] 80 }

  condition:
    any of them
}