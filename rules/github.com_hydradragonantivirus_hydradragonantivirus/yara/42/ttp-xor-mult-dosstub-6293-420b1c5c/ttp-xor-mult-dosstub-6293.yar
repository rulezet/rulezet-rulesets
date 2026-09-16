rule TTP_XOR_MULT_DOSStub_6293 {
  strings:
    $key_6293 = { 36 fb [2] 42 e3 [2] 05 e1 [2] 42 f0 [2] 0c fc [2] 00 f6 [2] 17 fd [2] 0c b3 [2] 31 }

  condition:
    any of them
}