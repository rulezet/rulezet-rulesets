rule TTP_XOR_MULT_DOSStub_8493 {
  strings:
    $key_8493 = { d0 fb [2] a4 e3 [2] e3 e1 [2] a4 f0 [2] ea fc [2] e6 f6 [2] f1 fd [2] ea b3 [2] d7 }

  condition:
    any of them
}