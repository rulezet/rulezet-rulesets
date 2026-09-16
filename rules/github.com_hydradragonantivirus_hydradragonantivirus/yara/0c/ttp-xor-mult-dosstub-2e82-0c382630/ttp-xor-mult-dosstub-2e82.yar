rule TTP_XOR_MULT_DOSStub_2e82 {
  strings:
    $key_2e82 = { 7a ea [2] 0e f2 [2] 49 f0 [2] 0e e1 [2] 40 ed [2] 4c e7 [2] 5b ec [2] 40 a2 [2] 7d }

  condition:
    any of them
}