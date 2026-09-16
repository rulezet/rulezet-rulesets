rule TTP_XOR_MULT_DOSStub_b590 {
  strings:
    $key_b590 = { e1 f8 [2] 95 e0 [2] d2 e2 [2] 95 f3 [2] db ff [2] d7 f5 [2] c0 fe [2] db b0 [2] e6 }

  condition:
    any of them
}