rule TTP_XOR_MULT_DOSStub_3393 {
  strings:
    $key_3393 = { 67 fb [2] 13 e3 [2] 54 e1 [2] 13 f0 [2] 5d fc [2] 51 f6 [2] 46 fd [2] 5d b3 [2] 60 }

  condition:
    any of them
}