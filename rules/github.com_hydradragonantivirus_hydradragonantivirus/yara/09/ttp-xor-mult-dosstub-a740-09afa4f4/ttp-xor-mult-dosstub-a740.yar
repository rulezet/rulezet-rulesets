rule TTP_XOR_MULT_DOSStub_a740 {
  strings:
    $key_a740 = { f3 28 [2] 87 30 [2] c0 32 [2] 87 23 [2] c9 2f [2] c5 25 [2] d2 2e [2] c9 60 [2] f4 }

  condition:
    any of them
}