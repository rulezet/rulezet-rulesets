rule TTP_XOR_MULT_DOSStub_d393 {
  strings:
    $key_d393 = { 87 fb [2] f3 e3 [2] b4 e1 [2] f3 f0 [2] bd fc [2] b1 f6 [2] a6 fd [2] bd b3 [2] 80 }

  condition:
    any of them
}