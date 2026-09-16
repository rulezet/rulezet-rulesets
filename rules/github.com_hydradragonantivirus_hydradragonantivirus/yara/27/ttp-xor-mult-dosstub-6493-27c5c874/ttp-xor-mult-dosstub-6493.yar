rule TTP_XOR_MULT_DOSStub_6493 {
  strings:
    $key_6493 = { 30 fb [2] 44 e3 [2] 03 e1 [2] 44 f0 [2] 0a fc [2] 06 f6 [2] 11 fd [2] 0a b3 [2] 37 }

  condition:
    any of them
}