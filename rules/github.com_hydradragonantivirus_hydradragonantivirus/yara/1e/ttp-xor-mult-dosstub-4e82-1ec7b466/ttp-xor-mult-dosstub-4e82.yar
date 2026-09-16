rule TTP_XOR_MULT_DOSStub_4e82 {
  strings:
    $key_4e82 = { 1a ea [2] 6e f2 [2] 29 f0 [2] 6e e1 [2] 20 ed [2] 2c e7 [2] 3b ec [2] 20 a2 [2] 1d }

  condition:
    any of them
}