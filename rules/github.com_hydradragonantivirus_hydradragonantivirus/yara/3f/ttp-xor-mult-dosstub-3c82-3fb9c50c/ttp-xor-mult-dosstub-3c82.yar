rule TTP_XOR_MULT_DOSStub_3c82 {
  strings:
    $key_3c82 = { 68 ea [2] 1c f2 [2] 5b f0 [2] 1c e1 [2] 52 ed [2] 5e e7 [2] 49 ec [2] 52 a2 [2] 6f }

  condition:
    any of them
}