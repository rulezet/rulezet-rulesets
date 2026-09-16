rule TTP_XOR_MULT_DOSStub_5493 {
  strings:
    $key_5493 = { 00 fb [2] 74 e3 [2] 33 e1 [2] 74 f0 [2] 3a fc [2] 36 f6 [2] 21 fd [2] 3a b3 [2] 07 }

  condition:
    any of them
}