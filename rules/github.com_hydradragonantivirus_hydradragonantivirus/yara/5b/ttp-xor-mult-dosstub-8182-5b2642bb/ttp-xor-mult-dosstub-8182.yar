rule TTP_XOR_MULT_DOSStub_8182 {
  strings:
    $key_8182 = { d5 ea [2] a1 f2 [2] e6 f0 [2] a1 e1 [2] ef ed [2] e3 e7 [2] f4 ec [2] ef a2 [2] d2 }

  condition:
    any of them
}