rule TTP_XOR_MULT_DOSStub_838b {
  strings:
    $key_838b = { d7 e3 [2] a3 fb [2] e4 f9 [2] a3 e8 [2] ed e4 [2] e1 ee [2] f6 e5 [2] ed ab [2] d0 }

  condition:
    any of them
}