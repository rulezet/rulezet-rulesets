rule TTP_XOR_MULT_DOSStub_a49e {
  strings:
    $key_a49e = { f0 f6 [2] 84 ee [2] c3 ec [2] 84 fd [2] ca f1 [2] c6 fb [2] d1 f0 [2] ca be [2] f7 }

  condition:
    any of them
}