rule TTP_XOR_MULT_DOSStub_7c9e {
  strings:
    $key_7c9e = { 28 f6 [2] 5c ee [2] 1b ec [2] 5c fd [2] 12 f1 [2] 1e fb [2] 09 f0 [2] 12 be [2] 2f }

  condition:
    any of them
}