rule TTP_XOR_MULT_DOSStub_4390 {
  strings:
    $key_4390 = { 17 f8 [2] 63 e0 [2] 24 e2 [2] 63 f3 [2] 2d ff [2] 21 f5 [2] 36 fe [2] 2d b0 [2] 10 }

  condition:
    any of them
}