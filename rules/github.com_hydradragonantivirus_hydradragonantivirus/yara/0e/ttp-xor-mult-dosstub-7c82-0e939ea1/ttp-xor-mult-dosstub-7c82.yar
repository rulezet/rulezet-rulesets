rule TTP_XOR_MULT_DOSStub_7c82 {
  strings:
    $key_7c82 = { 28 ea [2] 5c f2 [2] 1b f0 [2] 5c e1 [2] 12 ed [2] 1e e7 [2] 09 ec [2] 12 a2 [2] 2f }

  condition:
    any of them
}