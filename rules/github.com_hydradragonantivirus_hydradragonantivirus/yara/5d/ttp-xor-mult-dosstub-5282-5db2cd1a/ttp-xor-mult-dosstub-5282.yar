rule TTP_XOR_MULT_DOSStub_5282 {
  strings:
    $key_5282 = { 06 ea [2] 72 f2 [2] 35 f0 [2] 72 e1 [2] 3c ed [2] 30 e7 [2] 27 ec [2] 3c a2 [2] 01 }

  condition:
    any of them
}