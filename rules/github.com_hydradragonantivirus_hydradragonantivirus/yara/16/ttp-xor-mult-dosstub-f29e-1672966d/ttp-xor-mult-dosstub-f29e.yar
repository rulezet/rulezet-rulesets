rule TTP_XOR_MULT_DOSStub_f29e {
  strings:
    $key_f29e = { a6 f6 [2] d2 ee [2] 95 ec [2] d2 fd [2] 9c f1 [2] 90 fb [2] 87 f0 [2] 9c be [2] a1 }

  condition:
    any of them
}