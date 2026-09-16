rule TTP_XOR_MULT_DOSStub_a28b {
  strings:
    $key_a28b = { f6 e3 [2] 82 fb [2] c5 f9 [2] 82 e8 [2] cc e4 [2] c0 ee [2] d7 e5 [2] cc ab [2] f1 }

  condition:
    any of them
}