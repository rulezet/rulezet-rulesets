rule TTP_XOR_MULT_DOSStub_848b {
  strings:
    $key_848b = { d0 e3 [2] a4 fb [2] e3 f9 [2] a4 e8 [2] ea e4 [2] e6 ee [2] f1 e5 [2] ea ab [2] d7 }

  condition:
    any of them
}