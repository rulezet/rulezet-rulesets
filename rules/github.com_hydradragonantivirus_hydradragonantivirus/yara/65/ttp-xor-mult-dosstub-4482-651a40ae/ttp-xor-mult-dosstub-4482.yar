rule TTP_XOR_MULT_DOSStub_4482 {
  strings:
    $key_4482 = { 10 ea [2] 64 f2 [2] 23 f0 [2] 64 e1 [2] 2a ed [2] 26 e7 [2] 31 ec [2] 2a a2 [2] 17 }

  condition:
    any of them
}