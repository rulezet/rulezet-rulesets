rule TTP_XOR_MULT_DOSStub_a29a {
  strings:
    $key_a29a = { f6 f2 [2] 82 ea [2] c5 e8 [2] 82 f9 [2] cc f5 [2] c0 ff [2] d7 f4 [2] cc ba [2] f1 }

  condition:
    any of them
}