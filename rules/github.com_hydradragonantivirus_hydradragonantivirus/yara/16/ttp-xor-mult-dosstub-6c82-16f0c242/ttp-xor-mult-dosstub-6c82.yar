rule TTP_XOR_MULT_DOSStub_6c82 {
  strings:
    $key_6c82 = { 38 ea [2] 4c f2 [2] 0b f0 [2] 4c e1 [2] 02 ed [2] 0e e7 [2] 19 ec [2] 02 a2 [2] 3f }

  condition:
    any of them
}