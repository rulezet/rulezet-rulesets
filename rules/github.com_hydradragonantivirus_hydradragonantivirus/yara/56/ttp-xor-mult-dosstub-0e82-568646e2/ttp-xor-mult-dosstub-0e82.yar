rule TTP_XOR_MULT_DOSStub_0e82 {
  strings:
    $key_0e82 = { 5a ea [2] 2e f2 [2] 69 f0 [2] 2e e1 [2] 60 ed [2] 6c e7 [2] 7b ec [2] 60 a2 [2] 5d }

  condition:
    any of them
}