rule TTP_XOR_MULT_DOSStub_d182 {
  strings:
    $key_d182 = { 85 ea [2] f1 f2 [2] b6 f0 [2] f1 e1 [2] bf ed [2] b3 e7 [2] a4 ec [2] bf a2 [2] 82 }

  condition:
    any of them
}