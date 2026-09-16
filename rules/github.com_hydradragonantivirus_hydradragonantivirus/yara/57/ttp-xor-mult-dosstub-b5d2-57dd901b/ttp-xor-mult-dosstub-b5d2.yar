rule TTP_XOR_MULT_DOSStub_b5d2 {
  strings:
    $key_b5d2 = { e1 ba [2] 95 a2 [2] d2 a0 [2] 95 b1 [2] db bd [2] d7 b7 [2] c0 bc [2] db f2 [2] e6 }

  condition:
    any of them
}