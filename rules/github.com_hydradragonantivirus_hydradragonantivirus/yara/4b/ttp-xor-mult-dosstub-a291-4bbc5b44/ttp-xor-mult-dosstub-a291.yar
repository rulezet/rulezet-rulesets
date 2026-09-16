rule TTP_XOR_MULT_DOSStub_a291 {
  strings:
    $key_a291 = { f6 f9 [2] 82 e1 [2] c5 e3 [2] 82 f2 [2] cc fe [2] c0 f4 [2] d7 ff [2] cc b1 [2] f1 }

  condition:
    any of them
}