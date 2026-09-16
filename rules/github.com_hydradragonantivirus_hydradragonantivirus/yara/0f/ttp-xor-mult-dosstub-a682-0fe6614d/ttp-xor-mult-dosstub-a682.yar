rule TTP_XOR_MULT_DOSStub_a682 {
  strings:
    $key_a682 = { f2 ea [2] 86 f2 [2] c1 f0 [2] 86 e1 [2] c8 ed [2] c4 e7 [2] d3 ec [2] c8 a2 [2] f5 }

  condition:
    any of them
}