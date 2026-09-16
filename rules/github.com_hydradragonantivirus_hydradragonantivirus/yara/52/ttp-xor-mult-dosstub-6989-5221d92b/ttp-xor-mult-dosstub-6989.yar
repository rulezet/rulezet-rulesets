rule TTP_XOR_MULT_DOSStub_6989 {
  strings:
    $key_6989 = { 3d e1 [2] 49 f9 [2] 0e fb [2] 49 ea [2] 07 e6 [2] 0b ec [2] 1c e7 [2] 07 a9 [2] 3a }

  condition:
    any of them
}