rule TTP_XOR_MULT_DOSStub_f19e {
  strings:
    $key_f19e = { a5 f6 [2] d1 ee [2] 96 ec [2] d1 fd [2] 9f f1 [2] 93 fb [2] 84 f0 [2] 9f be [2] a2 }

  condition:
    any of them
}