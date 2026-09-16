rule TTP_XOR_MULT_DOSStub_7793 {
  strings:
    $key_7793 = { 23 fb [2] 57 e3 [2] 10 e1 [2] 57 f0 [2] 19 fc [2] 15 f6 [2] 02 fd [2] 19 b3 [2] 24 }

  condition:
    any of them
}