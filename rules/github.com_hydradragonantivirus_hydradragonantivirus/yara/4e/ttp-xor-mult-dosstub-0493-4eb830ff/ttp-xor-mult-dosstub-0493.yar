rule TTP_XOR_MULT_DOSStub_0493 {
  strings:
    $key_0493 = { 50 fb [2] 24 e3 [2] 63 e1 [2] 24 f0 [2] 6a fc [2] 66 f6 [2] 71 fd [2] 6a b3 [2] 57 }

  condition:
    any of them
}