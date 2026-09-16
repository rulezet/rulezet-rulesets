rule TTP_XOR_MULT_DOSStub_1482 {
  strings:
    $key_1482 = { 40 ea [2] 34 f2 [2] 73 f0 [2] 34 e1 [2] 7a ed [2] 76 e7 [2] 61 ec [2] 7a a2 [2] 47 }

  condition:
    any of them
}