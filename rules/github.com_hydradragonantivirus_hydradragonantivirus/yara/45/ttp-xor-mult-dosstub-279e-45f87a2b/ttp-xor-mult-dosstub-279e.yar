rule TTP_XOR_MULT_DOSStub_279e {
  strings:
    $key_279e = { 73 f6 [2] 07 ee [2] 40 ec [2] 07 fd [2] 49 f1 [2] 45 fb [2] 52 f0 [2] 49 be [2] 74 }

  condition:
    any of them
}