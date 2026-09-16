rule TTP_XOR_MULT_DOSStub_2889 {
  strings:
    $key_2889 = { 7c e1 [2] 08 f9 [2] 4f fb [2] 08 ea [2] 46 e6 [2] 4a ec [2] 5d e7 [2] 46 a9 [2] 7b }

  condition:
    any of them
}