rule TTP_XOR_MULT_DOSStub_159e {
  strings:
    $key_159e = { 41 f6 [2] 35 ee [2] 72 ec [2] 35 fd [2] 7b f1 [2] 77 fb [2] 60 f0 [2] 7b be [2] 46 }

  condition:
    any of them
}