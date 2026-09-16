rule TTP_XOR_MULT_DOSStub_6c9e {
  strings:
    $key_6c9e = { 38 f6 [2] 4c ee [2] 0b ec [2] 4c fd [2] 02 f1 [2] 0e fb [2] 19 f0 [2] 02 be [2] 3f }

  condition:
    any of them
}