rule TTP_XOR_MULT_DOSStub_a459 {
  strings:
    $key_a459 = { f0 31 [2] 84 29 [2] c3 2b [2] 84 3a [2] ca 36 [2] c6 3c [2] d1 37 [2] ca 79 [2] f7 }

  condition:
    any of them
}