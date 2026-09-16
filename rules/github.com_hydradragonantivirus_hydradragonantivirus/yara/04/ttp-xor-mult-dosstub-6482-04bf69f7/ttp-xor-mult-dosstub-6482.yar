rule TTP_XOR_MULT_DOSStub_6482 {
  strings:
    $key_6482 = { 30 ea [2] 44 f2 [2] 03 f0 [2] 44 e1 [2] 0a ed [2] 06 e7 [2] 11 ec [2] 0a a2 [2] 37 }

  condition:
    any of them
}