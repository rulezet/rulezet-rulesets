rule TTP_XOR_MULT_DOSStub_a58f {
  strings:
    $key_a58f = { f1 e7 [2] 85 ff [2] c2 fd [2] 85 ec [2] cb e0 [2] c7 ea [2] d0 e1 [2] cb af [2] f6 }

  condition:
    any of them
}