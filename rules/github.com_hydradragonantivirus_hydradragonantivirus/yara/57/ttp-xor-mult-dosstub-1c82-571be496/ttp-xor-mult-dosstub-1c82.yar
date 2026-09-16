rule TTP_XOR_MULT_DOSStub_1c82 {
  strings:
    $key_1c82 = { 48 ea [2] 3c f2 [2] 7b f0 [2] 3c e1 [2] 72 ed [2] 7e e7 [2] 69 ec [2] 72 a2 [2] 4f }

  condition:
    any of them
}