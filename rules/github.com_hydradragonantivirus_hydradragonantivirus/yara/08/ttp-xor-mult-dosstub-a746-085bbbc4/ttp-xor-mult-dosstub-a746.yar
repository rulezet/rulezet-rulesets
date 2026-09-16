rule TTP_XOR_MULT_DOSStub_a746 {
  strings:
    $key_a746 = { f3 2e [2] 87 36 [2] c0 34 [2] 87 25 [2] c9 29 [2] c5 23 [2] d2 28 [2] c9 66 [2] f4 }

  condition:
    any of them
}