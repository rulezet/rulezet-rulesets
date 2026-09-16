rule TTP_XOR_MULT_DOSStub_f293 {
  strings:
    $key_f293 = { a6 fb [2] d2 e3 [2] 95 e1 [2] d2 f0 [2] 9c fc [2] 90 f6 [2] 87 fd [2] 9c b3 [2] a1 }

  condition:
    any of them
}