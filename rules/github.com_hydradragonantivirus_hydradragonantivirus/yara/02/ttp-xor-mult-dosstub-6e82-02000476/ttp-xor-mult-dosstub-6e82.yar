rule TTP_XOR_MULT_DOSStub_6e82 {
  strings:
    $key_6e82 = { 3a ea [2] 4e f2 [2] 09 f0 [2] 4e e1 [2] 00 ed [2] 0c e7 [2] 1b ec [2] 00 a2 [2] 3d }

  condition:
    any of them
}