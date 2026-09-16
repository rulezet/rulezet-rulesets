rule TTP_XOR_MULT_DOSStub_4c82 {
  strings:
    $key_4c82 = { 18 ea [2] 6c f2 [2] 2b f0 [2] 6c e1 [2] 22 ed [2] 2e e7 [2] 39 ec [2] 22 a2 [2] 1f }

  condition:
    any of them
}