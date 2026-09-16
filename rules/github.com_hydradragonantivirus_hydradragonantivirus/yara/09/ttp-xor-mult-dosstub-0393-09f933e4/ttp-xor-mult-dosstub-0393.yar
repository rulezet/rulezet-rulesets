rule TTP_XOR_MULT_DOSStub_0393 {
  strings:
    $key_0393 = { 57 fb [2] 23 e3 [2] 64 e1 [2] 23 f0 [2] 6d fc [2] 61 f6 [2] 76 fd [2] 6d b3 [2] 50 }

  condition:
    any of them
}