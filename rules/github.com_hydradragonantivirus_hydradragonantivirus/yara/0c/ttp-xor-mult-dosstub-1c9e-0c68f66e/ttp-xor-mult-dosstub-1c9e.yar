rule TTP_XOR_MULT_DOSStub_1c9e {
  strings:
    $key_1c9e = { 48 f6 [2] 3c ee [2] 7b ec [2] 3c fd [2] 72 f1 [2] 7e fb [2] 69 f0 [2] 72 be [2] 4f }

  condition:
    any of them
}