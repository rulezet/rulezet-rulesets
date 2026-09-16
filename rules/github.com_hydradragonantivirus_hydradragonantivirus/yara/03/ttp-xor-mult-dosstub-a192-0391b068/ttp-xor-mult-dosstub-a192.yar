rule TTP_XOR_MULT_DOSStub_a192 {
  strings:
    $key_a192 = { f5 fa [2] 81 e2 [2] c6 e0 [2] 81 f1 [2] cf fd [2] c3 f7 [2] d4 fc [2] cf b2 [2] f2 }

  condition:
    any of them
}