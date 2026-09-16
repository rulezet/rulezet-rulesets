rule TTP_XOR_MULT_DOSStub_a490 {
  strings:
    $key_a490 = { f0 f8 [2] 84 e0 [2] c3 e2 [2] 84 f3 [2] ca ff [2] c6 f5 [2] d1 fe [2] ca b0 [2] f7 }

  condition:
    any of them
}