rule TTP_XOR_MULT_DOSStub_828b {
  strings:
    $key_828b = { d6 e3 [2] a2 fb [2] e5 f9 [2] a2 e8 [2] ec e4 [2] e0 ee [2] f7 e5 [2] ec ab [2] d1 }

  condition:
    any of them
}