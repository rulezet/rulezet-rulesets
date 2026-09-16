rule TTP_XOR_MULT_DOSStub_e382 {
  strings:
    $key_e382 = { b7 ea [2] c3 f2 [2] 84 f0 [2] c3 e1 [2] 8d ed [2] 81 e7 [2] 96 ec [2] 8d a2 [2] b0 }

  condition:
    any of them
}