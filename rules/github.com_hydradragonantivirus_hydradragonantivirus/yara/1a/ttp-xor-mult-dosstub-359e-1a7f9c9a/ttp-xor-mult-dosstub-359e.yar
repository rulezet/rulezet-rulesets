rule TTP_XOR_MULT_DOSStub_359e {
  strings:
    $key_359e = { 61 f6 [2] 15 ee [2] 52 ec [2] 15 fd [2] 5b f1 [2] 57 fb [2] 40 f0 [2] 5b be [2] 66 }

  condition:
    any of them
}