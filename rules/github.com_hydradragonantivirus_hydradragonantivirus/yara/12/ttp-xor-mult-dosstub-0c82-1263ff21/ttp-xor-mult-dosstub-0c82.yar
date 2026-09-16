rule TTP_XOR_MULT_DOSStub_0c82 {
  strings:
    $key_0c82 = { 58 ea [2] 2c f2 [2] 6b f0 [2] 2c e1 [2] 62 ed [2] 6e e7 [2] 79 ec [2] 62 a2 [2] 5f }

  condition:
    any of them
}