rule TTP_XOR_MULT_DOSStub_4691 {
  strings:
    $key_4691 = { 12 f9 [2] 66 e1 [2] 21 e3 [2] 66 f2 [2] 28 fe [2] 24 f4 [2] 33 ff [2] 28 b1 [2] 15 }

  condition:
    any of them
}