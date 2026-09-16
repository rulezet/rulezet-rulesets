rule TTP_XOR_MULT_DOSStub_d39e {
  strings:
    $key_d39e = { 87 f6 [2] f3 ee [2] b4 ec [2] f3 fd [2] bd f1 [2] b1 fb [2] a6 f0 [2] bd be [2] 80 }

  condition:
    any of them
}