rule TTP_XOR_MULT_DOSStub_1390 {
  strings:
    $key_1390 = { 47 f8 [2] 33 e0 [2] 74 e2 [2] 33 f3 [2] 7d ff [2] 71 f5 [2] 66 fe [2] 7d b0 [2] 40 }

  condition:
    any of them
}