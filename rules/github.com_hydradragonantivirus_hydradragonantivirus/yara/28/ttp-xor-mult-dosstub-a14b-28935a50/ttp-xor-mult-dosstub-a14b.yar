rule TTP_XOR_MULT_DOSStub_a14b {
  strings:
    $key_a14b = { f5 23 [2] 81 3b [2] c6 39 [2] 81 28 [2] cf 24 [2] c3 2e [2] d4 25 [2] cf 6b [2] f2 }

  condition:
    any of them
}