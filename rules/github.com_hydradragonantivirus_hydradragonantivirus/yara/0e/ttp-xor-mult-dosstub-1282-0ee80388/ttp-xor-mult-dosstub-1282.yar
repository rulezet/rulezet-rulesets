rule TTP_XOR_MULT_DOSStub_1282 {
  strings:
    $key_1282 = { 46 ea [2] 32 f2 [2] 75 f0 [2] 32 e1 [2] 7c ed [2] 70 e7 [2] 67 ec [2] 7c a2 [2] 41 }

  condition:
    any of them
}