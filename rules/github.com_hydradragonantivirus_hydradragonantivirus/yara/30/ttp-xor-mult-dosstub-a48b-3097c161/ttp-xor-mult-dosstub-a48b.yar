rule TTP_XOR_MULT_DOSStub_a48b {
  strings:
    $key_a48b = { f0 e3 [2] 84 fb [2] c3 f9 [2] 84 e8 [2] ca e4 [2] c6 ee [2] d1 e5 [2] ca ab [2] f7 }

  condition:
    any of them
}