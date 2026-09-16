rule TTP_XOR_MULT_DOSStub_2498 {
  strings:
    $key_2498 = { 70 f0 [2] 04 e8 [2] 43 ea [2] 04 fb [2] 4a f7 [2] 46 fd [2] 51 f6 [2] 4a b8 [2] 77 }

  condition:
    any of them
}