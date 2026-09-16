rule TTP_XOR_MULT_DOSStub_23d0 {
  strings:
    $key_23d0 = { 77 b8 [2] 03 a0 [2] 44 a2 [2] 03 b3 [2] 4d bf [2] 41 b5 [2] 56 be [2] 4d f0 [2] 70 }

  condition:
    any of them
}