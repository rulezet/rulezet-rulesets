rule TTP_XOR_MULT_DOSStub_a2d9 {
  strings:
    $key_a2d9 = { f6 b1 [2] 82 a9 [2] c5 ab [2] 82 ba [2] cc b6 [2] c0 bc [2] d7 b7 [2] cc f9 [2] f1 }

  condition:
    any of them
}