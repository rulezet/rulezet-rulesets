rule TTP_XOR_MULT_DOSStub_c59e {
  strings:
    $key_c59e = { 91 f6 [2] e5 ee [2] a2 ec [2] e5 fd [2] ab f1 [2] a7 fb [2] b0 f0 [2] ab be [2] 96 }

  condition:
    any of them
}