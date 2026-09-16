rule TTP_XOR_MULT_DOSStub_2390 {
  strings:
    $key_2390 = { 77 f8 [2] 03 e0 [2] 44 e2 [2] 03 f3 [2] 4d ff [2] 41 f5 [2] 56 fe [2] 4d b0 [2] 70 }

  condition:
    any of them
}