rule TTP_XOR_MULT_DOSStub_e582 {
  strings:
    $key_e582 = { b1 ea [2] c5 f2 [2] 82 f0 [2] c5 e1 [2] 8b ed [2] 87 e7 [2] 90 ec [2] 8b a2 [2] b6 }

  condition:
    any of them
}