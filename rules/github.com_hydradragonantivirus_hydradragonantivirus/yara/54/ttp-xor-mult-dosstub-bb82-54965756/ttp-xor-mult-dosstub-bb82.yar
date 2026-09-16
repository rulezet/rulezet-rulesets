rule TTP_XOR_MULT_DOSStub_bb82 {
  strings:
    $key_bb82 = { ef ea [2] 9b f2 [2] dc f0 [2] 9b e1 [2] d5 ed [2] d9 e7 [2] ce ec [2] d5 a2 [2] e8 }

  condition:
    any of them
}