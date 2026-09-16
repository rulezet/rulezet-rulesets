rule TTP_XOR_MULT_DOSStub_4493 {
  strings:
    $key_4493 = { 10 fb [2] 64 e3 [2] 23 e1 [2] 64 f0 [2] 2a fc [2] 26 f6 [2] 31 fd [2] 2a b3 [2] 17 }

  condition:
    any of them
}