rule TTP_XOR_MULT_DOSStub_a726 {
  strings:
    $key_a726 = { f3 4e [2] 87 56 [2] c0 54 [2] 87 45 [2] c9 49 [2] c5 43 [2] d2 48 [2] c9 06 [2] f4 }

  condition:
    any of them
}