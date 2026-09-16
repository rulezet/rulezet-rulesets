rule TTP_XOR_MULT_DOSStub_7093 {
  strings:
    $key_7093 = { 24 fb [2] 50 e3 [2] 17 e1 [2] 50 f0 [2] 1e fc [2] 12 f6 [2] 05 fd [2] 1e b3 [2] 23 }

  condition:
    any of them
}