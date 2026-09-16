rule TTP_XOR_MULT_DOSStub_b591 {
  strings:
    $key_b591 = { e1 f9 [2] 95 e1 [2] d2 e3 [2] 95 f2 [2] db fe [2] d7 f4 [2] c0 ff [2] db b1 [2] e6 }

  condition:
    any of them
}