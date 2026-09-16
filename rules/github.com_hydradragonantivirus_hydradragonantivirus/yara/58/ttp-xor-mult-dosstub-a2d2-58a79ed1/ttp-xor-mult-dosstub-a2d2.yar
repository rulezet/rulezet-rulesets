rule TTP_XOR_MULT_DOSStub_a2d2 {
  strings:
    $key_a2d2 = { f6 ba [2] 82 a2 [2] c5 a0 [2] 82 b1 [2] cc bd [2] c0 b7 [2] d7 bc [2] cc f2 [2] f1 }

  condition:
    any of them
}