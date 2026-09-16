rule TTP_XOR_MULT_DOSStub_23d2 {
  strings:
    $key_23d2 = { 77 ba [2] 03 a2 [2] 44 a0 [2] 03 b1 [2] 4d bd [2] 41 b7 [2] 56 bc [2] 4d f2 [2] 70 }

  condition:
    any of them
}