rule TTP_XOR_MULT_DOSStub_80d9 {
  strings:
    $key_80d9 = { d4 b1 [2] a0 a9 [2] e7 ab [2] a0 ba [2] ee b6 [2] e2 bc [2] f5 b7 [2] ee f9 [2] d3 }

  condition:
    any of them
}