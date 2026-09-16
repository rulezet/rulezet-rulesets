rule TTP_XOR_MULT_DOSStub_f49e {
  strings:
    $key_f49e = { a0 f6 [2] d4 ee [2] 93 ec [2] d4 fd [2] 9a f1 [2] 96 fb [2] 81 f0 [2] 9a be [2] a7 }

  condition:
    any of them
}