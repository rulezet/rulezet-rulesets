rule TTP_XOR_MULT_DOSStub_c39e {
  strings:
    $key_c39e = { 97 f6 [2] e3 ee [2] a4 ec [2] e3 fd [2] ad f1 [2] a1 fb [2] b6 f0 [2] ad be [2] 90 }

  condition:
    any of them
}