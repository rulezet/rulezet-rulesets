rule TTP_XOR_MULT_DOSStub_219e {
  strings:
    $key_219e = { 75 f6 [2] 01 ee [2] 46 ec [2] 01 fd [2] 4f f1 [2] 43 fb [2] 54 f0 [2] 4f be [2] 72 }

  condition:
    any of them
}