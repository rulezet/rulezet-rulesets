rule TTP_XOR_MULT_DOSStub_a3ca {
  strings:
    $key_a3ca = { f7 a2 [2] 83 ba [2] c4 b8 [2] 83 a9 [2] cd a5 [2] c1 af [2] d6 a4 [2] cd ea [2] f0 }

  condition:
    any of them
}