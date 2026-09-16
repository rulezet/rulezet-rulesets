rule TTP_XOR_MULT_DOSStub_f39e {
  strings:
    $key_f39e = { a7 f6 [2] d3 ee [2] 94 ec [2] d3 fd [2] 9d f1 [2] 91 fb [2] 86 f0 [2] 9d be [2] a0 }

  condition:
    any of them
}