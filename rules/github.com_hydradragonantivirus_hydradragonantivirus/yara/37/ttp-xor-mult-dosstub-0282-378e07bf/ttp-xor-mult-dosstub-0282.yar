rule TTP_XOR_MULT_DOSStub_0282 {
  strings:
    $key_0282 = { 56 ea [2] 22 f2 [2] 65 f0 [2] 22 e1 [2] 6c ed [2] 60 e7 [2] 77 ec [2] 6c a2 [2] 51 }

  condition:
    any of them
}