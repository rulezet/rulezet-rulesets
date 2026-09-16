rule TTP_XOR_MULT_DOSStub_a497 {
  strings:
    $key_a497 = { f0 ff [2] 84 e7 [2] c3 e5 [2] 84 f4 [2] ca f8 [2] c6 f2 [2] d1 f9 [2] ca b7 [2] f7 }

  condition:
    any of them
}