rule TTP_XOR_MULT_DOSStub_f69e {
  strings:
    $key_f69e = { a2 f6 [2] d6 ee [2] 91 ec [2] d6 fd [2] 98 f1 [2] 94 fb [2] 83 f0 [2] 98 be [2] a5 }

  condition:
    any of them
}