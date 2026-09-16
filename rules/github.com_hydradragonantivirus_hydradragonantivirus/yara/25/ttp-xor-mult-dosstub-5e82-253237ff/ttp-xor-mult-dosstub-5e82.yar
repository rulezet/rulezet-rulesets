rule TTP_XOR_MULT_DOSStub_5e82 {
  strings:
    $key_5e82 = { 0a ea [2] 7e f2 [2] 39 f0 [2] 7e e1 [2] 30 ed [2] 3c e7 [2] 2b ec [2] 30 a2 [2] 0d }

  condition:
    any of them
}