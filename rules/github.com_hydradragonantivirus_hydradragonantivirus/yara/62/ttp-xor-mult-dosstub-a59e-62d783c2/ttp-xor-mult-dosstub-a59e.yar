rule TTP_XOR_MULT_DOSStub_a59e {
  strings:
    $key_a59e = { f1 f6 [2] 85 ee [2] c2 ec [2] 85 fd [2] cb f1 [2] c7 fb [2] d0 f0 [2] cb be [2] f6 }

  condition:
    any of them
}