rule TTP_XOR_MULT_DOSStub_e691 {
  strings:
    $key_e691 = { b2 f9 [2] c6 e1 [2] 81 e3 [2] c6 f2 [2] 88 fe [2] 84 f4 [2] 93 ff [2] 88 b1 [2] b5 }

  condition:
    any of them
}