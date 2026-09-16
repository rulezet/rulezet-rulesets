rule TTP_XOR_MULT_DOSStub_859e {
  strings:
    $key_859e = { d1 f6 [2] a5 ee [2] e2 ec [2] a5 fd [2] eb f1 [2] e7 fb [2] f0 f0 [2] eb be [2] d6 }

  condition:
    any of them
}