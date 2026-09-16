rule TTP_XOR_MULT_DOSStub_b682 {
  strings:
    $key_b682 = { e2 ea [2] 96 f2 [2] d1 f0 [2] 96 e1 [2] d8 ed [2] d4 e7 [2] c3 ec [2] d8 a2 [2] e5 }

  condition:
    any of them
}