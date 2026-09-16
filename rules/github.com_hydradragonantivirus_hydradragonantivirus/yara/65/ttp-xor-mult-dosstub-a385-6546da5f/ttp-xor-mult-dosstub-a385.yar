rule TTP_XOR_MULT_DOSStub_a385 {
  strings:
    $key_a385 = { f7 ed [2] 83 f5 [2] c4 f7 [2] 83 e6 [2] cd ea [2] c1 e0 [2] d6 eb [2] cd a5 [2] f0 }

  condition:
    any of them
}