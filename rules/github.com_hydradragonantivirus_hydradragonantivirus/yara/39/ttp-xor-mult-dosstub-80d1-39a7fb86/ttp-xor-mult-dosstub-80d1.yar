rule TTP_XOR_MULT_DOSStub_80d1 {
  strings:
    $key_80d1 = { d4 b9 [2] a0 a1 [2] e7 a3 [2] a0 b2 [2] ee be [2] e2 b4 [2] f5 bf [2] ee f1 [2] d3 }

  condition:
    any of them
}