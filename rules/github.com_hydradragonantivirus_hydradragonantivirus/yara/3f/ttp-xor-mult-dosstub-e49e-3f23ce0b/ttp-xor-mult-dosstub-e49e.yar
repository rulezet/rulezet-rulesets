rule TTP_XOR_MULT_DOSStub_e49e {
  strings:
    $key_e49e = { b0 f6 [2] c4 ee [2] 83 ec [2] c4 fd [2] 8a f1 [2] 86 fb [2] 91 f0 [2] 8a be [2] b7 }

  condition:
    any of them
}