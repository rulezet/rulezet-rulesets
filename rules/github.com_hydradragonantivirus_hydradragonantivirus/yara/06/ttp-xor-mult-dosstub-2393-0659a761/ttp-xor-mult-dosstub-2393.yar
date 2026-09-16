rule TTP_XOR_MULT_DOSStub_2393 {
  strings:
    $key_2393 = { 77 fb [2] 03 e3 [2] 44 e1 [2] 03 f0 [2] 4d fc [2] 41 f6 [2] 56 fd [2] 4d b3 [2] 70 }

  condition:
    any of them
}