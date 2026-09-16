rule TTP_XOR_MULT_DOSStub_a78b {
  strings:
    $key_a78b = { f3 e3 [2] 87 fb [2] c0 f9 [2] 87 e8 [2] c9 e4 [2] c5 ee [2] d2 e5 [2] c9 ab [2] f4 }

  condition:
    any of them
}