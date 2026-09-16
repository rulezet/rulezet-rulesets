rule TTP_XOR_MULT_DOSStub_2495 {
  strings:
    $key_2495 = { 70 fd [2] 04 e5 [2] 43 e7 [2] 04 f6 [2] 4a fa [2] 46 f0 [2] 51 fb [2] 4a b5 [2] 77 }

  condition:
    any of them
}