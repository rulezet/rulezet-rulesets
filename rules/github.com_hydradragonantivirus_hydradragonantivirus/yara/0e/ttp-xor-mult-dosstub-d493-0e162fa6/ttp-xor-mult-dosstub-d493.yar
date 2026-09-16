rule TTP_XOR_MULT_DOSStub_d493 {
  strings:
    $key_d493 = { 80 fb [2] f4 e3 [2] b3 e1 [2] f4 f0 [2] ba fc [2] b6 f6 [2] a1 fd [2] ba b3 [2] 87 }

  condition:
    any of them
}