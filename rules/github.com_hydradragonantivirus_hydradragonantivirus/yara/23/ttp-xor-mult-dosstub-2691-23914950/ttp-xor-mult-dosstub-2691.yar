rule TTP_XOR_MULT_DOSStub_2691 {
  strings:
    $key_2691 = { 72 f9 [2] 06 e1 [2] 41 e3 [2] 06 f2 [2] 48 fe [2] 44 f4 [2] 53 ff [2] 48 b1 [2] 75 }

  condition:
    any of them
}