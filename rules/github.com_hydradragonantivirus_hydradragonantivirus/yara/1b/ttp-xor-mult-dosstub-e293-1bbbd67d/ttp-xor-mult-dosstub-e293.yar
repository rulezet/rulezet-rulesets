rule TTP_XOR_MULT_DOSStub_e293 {
  strings:
    $key_e293 = { b6 fb [2] c2 e3 [2] 85 e1 [2] c2 f0 [2] 8c fc [2] 80 f6 [2] 97 fd [2] 8c b3 [2] b1 }

  condition:
    any of them
}