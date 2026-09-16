rule TTP_XOR_MULT_DOSStub_5293 {
  strings:
    $key_5293 = { 06 fb [2] 72 e3 [2] 35 e1 [2] 72 f0 [2] 3c fc [2] 30 f6 [2] 27 fd [2] 3c b3 [2] 01 }

  condition:
    any of them
}