rule TTP_XOR_MULT_DOSStub_e282 {
  strings:
    $key_e282 = { b6 ea [2] c2 f2 [2] 85 f0 [2] c2 e1 [2] 8c ed [2] 80 e7 [2] 97 ec [2] 8c a2 [2] b1 }

  condition:
    any of them
}