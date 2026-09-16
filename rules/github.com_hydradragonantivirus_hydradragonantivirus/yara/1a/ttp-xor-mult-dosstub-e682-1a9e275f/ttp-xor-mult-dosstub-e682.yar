rule TTP_XOR_MULT_DOSStub_e682 {
  strings:
    $key_e682 = { b2 ea [2] c6 f2 [2] 81 f0 [2] c6 e1 [2] 88 ed [2] 84 e7 [2] 93 ec [2] 88 a2 [2] b5 }

  condition:
    any of them
}