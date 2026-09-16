rule TTP_XOR_MULT_DOSStub_809e {
  strings:
    $key_809e = { d4 f6 [2] a0 ee [2] e7 ec [2] a0 fd [2] ee f1 [2] e2 fb [2] f5 f0 [2] ee be [2] d3 }

  condition:
    any of them
}