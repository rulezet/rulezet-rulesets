rule TTP_XOR_MULT_DOSStub_e793 {
  strings:
    $key_e793 = { b3 fb [2] c7 e3 [2] 80 e1 [2] c7 f0 [2] 89 fc [2] 85 f6 [2] 92 fd [2] 89 b3 [2] b4 }

  condition:
    any of them
}