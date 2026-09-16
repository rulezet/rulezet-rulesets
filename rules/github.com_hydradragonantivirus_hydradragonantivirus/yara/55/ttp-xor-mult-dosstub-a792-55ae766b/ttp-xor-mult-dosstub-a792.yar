rule TTP_XOR_MULT_DOSStub_a792 {
  strings:
    $key_a792 = { f3 fa [2] 87 e2 [2] c0 e0 [2] 87 f1 [2] c9 fd [2] c5 f7 [2] d2 fc [2] c9 b2 [2] f4 }

  condition:
    any of them
}