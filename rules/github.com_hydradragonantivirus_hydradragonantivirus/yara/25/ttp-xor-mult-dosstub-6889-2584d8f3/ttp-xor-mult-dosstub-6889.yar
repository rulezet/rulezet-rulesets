rule TTP_XOR_MULT_DOSStub_6889 {
  strings:
    $key_6889 = { 3c e1 [2] 48 f9 [2] 0f fb [2] 48 ea [2] 06 e6 [2] 0a ec [2] 1d e7 [2] 06 a9 [2] 3b }

  condition:
    any of them
}