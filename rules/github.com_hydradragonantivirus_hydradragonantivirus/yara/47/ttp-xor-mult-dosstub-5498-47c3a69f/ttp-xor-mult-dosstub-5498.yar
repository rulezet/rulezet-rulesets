rule TTP_XOR_MULT_DOSStub_5498 {
  strings:
    $key_5498 = { 00 f0 [2] 74 e8 [2] 33 ea [2] 74 fb [2] 3a f7 [2] 36 fd [2] 21 f6 [2] 3a b8 [2] 07 }

  condition:
    any of them
}