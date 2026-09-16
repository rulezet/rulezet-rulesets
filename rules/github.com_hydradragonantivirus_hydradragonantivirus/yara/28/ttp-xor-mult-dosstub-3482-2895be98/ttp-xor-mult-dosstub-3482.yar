rule TTP_XOR_MULT_DOSStub_3482 {
  strings:
    $key_3482 = { 60 ea [2] 14 f2 [2] 53 f0 [2] 14 e1 [2] 5a ed [2] 56 e7 [2] 41 ec [2] 5a a2 [2] 67 }

  condition:
    any of them
}