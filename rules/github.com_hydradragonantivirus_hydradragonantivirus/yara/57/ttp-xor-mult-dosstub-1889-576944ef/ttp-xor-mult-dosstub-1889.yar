rule TTP_XOR_MULT_DOSStub_1889 {
  strings:
    $key_1889 = { 4c e1 [2] 38 f9 [2] 7f fb [2] 38 ea [2] 76 e6 [2] 7a ec [2] 6d e7 [2] 76 a9 [2] 4b }

  condition:
    any of them
}