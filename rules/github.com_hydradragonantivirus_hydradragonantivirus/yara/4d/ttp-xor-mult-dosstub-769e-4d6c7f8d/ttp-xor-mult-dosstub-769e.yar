rule TTP_XOR_MULT_DOSStub_769e {
  strings:
    $key_769e = { 22 f6 [2] 56 ee [2] 11 ec [2] 56 fd [2] 18 f1 [2] 14 fb [2] 03 f0 [2] 18 be [2] 25 }

  condition:
    any of them
}