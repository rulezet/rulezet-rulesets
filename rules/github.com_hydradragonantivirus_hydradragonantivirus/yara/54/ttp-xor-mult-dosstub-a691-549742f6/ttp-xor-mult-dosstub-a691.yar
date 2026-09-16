rule TTP_XOR_MULT_DOSStub_a691 {
  strings:
    $key_a691 = { f2 f9 [2] 86 e1 [2] c1 e3 [2] 86 f2 [2] c8 fe [2] c4 f4 [2] d3 ff [2] c8 b1 [2] f5 }

  condition:
    any of them
}