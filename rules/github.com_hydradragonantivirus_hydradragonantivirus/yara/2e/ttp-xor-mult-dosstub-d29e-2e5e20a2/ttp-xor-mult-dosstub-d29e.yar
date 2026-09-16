rule TTP_XOR_MULT_DOSStub_d29e {
  strings:
    $key_d29e = { 86 f6 [2] f2 ee [2] b5 ec [2] f2 fd [2] bc f1 [2] b0 fb [2] a7 f0 [2] bc be [2] 81 }

  condition:
    any of them
}