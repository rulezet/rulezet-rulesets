rule TTP_XOR_MULT_DOSStub_a18b {
  strings:
    $key_a18b = { f5 e3 [2] 81 fb [2] c6 f9 [2] 81 e8 [2] cf e4 [2] c3 ee [2] d4 e5 [2] cf ab [2] f2 }

  condition:
    any of them
}