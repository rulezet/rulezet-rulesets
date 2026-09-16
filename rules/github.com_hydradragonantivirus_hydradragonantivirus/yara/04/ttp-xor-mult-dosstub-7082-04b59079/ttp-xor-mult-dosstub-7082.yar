rule TTP_XOR_MULT_DOSStub_7082 {
  strings:
    $key_7082 = { 24 ea [2] 50 f2 [2] 17 f0 [2] 50 e1 [2] 1e ed [2] 12 e7 [2] 05 ec [2] 1e a2 [2] 23 }

  condition:
    any of them
}