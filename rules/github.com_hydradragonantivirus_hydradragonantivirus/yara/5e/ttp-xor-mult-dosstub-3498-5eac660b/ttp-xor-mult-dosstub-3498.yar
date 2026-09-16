rule TTP_XOR_MULT_DOSStub_3498 {
  strings:
    $key_3498 = { 60 f0 [2] 14 e8 [2] 53 ea [2] 14 fb [2] 5a f7 [2] 56 fd [2] 41 f6 [2] 5a b8 [2] 67 }

  condition:
    any of them
}