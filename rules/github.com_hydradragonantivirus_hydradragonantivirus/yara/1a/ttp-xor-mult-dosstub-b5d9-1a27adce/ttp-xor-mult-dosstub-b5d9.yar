rule TTP_XOR_MULT_DOSStub_b5d9 {
  strings:
    $key_b5d9 = { e1 b1 [2] 95 a9 [2] d2 ab [2] 95 ba [2] db b6 [2] d7 bc [2] c0 b7 [2] db f9 [2] e6 }

  condition:
    any of them
}