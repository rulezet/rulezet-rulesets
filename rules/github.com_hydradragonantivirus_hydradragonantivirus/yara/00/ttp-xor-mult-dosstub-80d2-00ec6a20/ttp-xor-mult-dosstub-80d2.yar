rule TTP_XOR_MULT_DOSStub_80d2 {
  strings:
    $key_80d2 = { d4 ba [2] a0 a2 [2] e7 a0 [2] a0 b1 [2] ee bd [2] e2 b7 [2] f5 bc [2] ee f2 [2] d3 }

  condition:
    any of them
}