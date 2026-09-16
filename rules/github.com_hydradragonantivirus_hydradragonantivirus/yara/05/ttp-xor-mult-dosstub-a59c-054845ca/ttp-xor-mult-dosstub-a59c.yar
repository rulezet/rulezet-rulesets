rule TTP_XOR_MULT_DOSStub_a59c {
  strings:
    $key_a59c = { f1 f4 [2] 85 ec [2] c2 ee [2] 85 ff [2] cb f3 [2] c7 f9 [2] d0 f2 [2] cb bc [2] f6 }

  condition:
    any of them
}