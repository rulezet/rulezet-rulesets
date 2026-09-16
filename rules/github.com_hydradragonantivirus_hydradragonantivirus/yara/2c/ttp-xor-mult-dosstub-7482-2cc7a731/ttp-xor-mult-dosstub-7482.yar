rule TTP_XOR_MULT_DOSStub_7482 {
  strings:
    $key_7482 = { 20 ea [2] 54 f2 [2] 13 f0 [2] 54 e1 [2] 1a ed [2] 16 e7 [2] 01 ec [2] 1a a2 [2] 27 }

  condition:
    any of them
}