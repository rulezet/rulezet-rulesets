rule TTP_XOR_MULT_DOSStub_b596 {
  strings:
    $key_b596 = { e1 fe [2] 95 e6 [2] d2 e4 [2] 95 f5 [2] db f9 [2] d7 f3 [2] c0 f8 [2] db b6 [2] e6 }

  condition:
    any of them
}