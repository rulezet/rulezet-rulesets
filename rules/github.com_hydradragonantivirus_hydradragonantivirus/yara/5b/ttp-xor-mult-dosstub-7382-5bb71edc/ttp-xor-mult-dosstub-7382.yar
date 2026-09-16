rule TTP_XOR_MULT_DOSStub_7382 {
  strings:
    $key_7382 = { 27 ea [2] 53 f2 [2] 14 f0 [2] 53 e1 [2] 1d ed [2] 11 e7 [2] 06 ec [2] 1d a2 [2] 20 }

  condition:
    any of them
}