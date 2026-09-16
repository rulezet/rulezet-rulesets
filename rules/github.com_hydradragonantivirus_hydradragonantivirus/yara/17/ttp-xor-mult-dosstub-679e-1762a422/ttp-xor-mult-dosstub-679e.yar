rule TTP_XOR_MULT_DOSStub_679e {
  strings:
    $key_679e = { 33 f6 [2] 47 ee [2] 00 ec [2] 47 fd [2] 09 f1 [2] 05 fb [2] 12 f0 [2] 09 be [2] 34 }

  condition:
    any of them
}