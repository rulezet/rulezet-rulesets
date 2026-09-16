rule TTP_XOR_MULT_DOSStub_a58d {
  strings:
    $key_a58d = { f1 e5 [2] 85 fd [2] c2 ff [2] 85 ee [2] cb e2 [2] c7 e8 [2] d0 e3 [2] cb ad [2] f6 }

  condition:
    any of them
}