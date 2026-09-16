rule TTP_XOR_MULT_DOSStub_8693 {
  strings:
    $key_8693 = { d2 fb [2] a6 e3 [2] e1 e1 [2] a6 f0 [2] e8 fc [2] e4 f6 [2] f3 fd [2] e8 b3 [2] d5 }

  condition:
    any of them
}