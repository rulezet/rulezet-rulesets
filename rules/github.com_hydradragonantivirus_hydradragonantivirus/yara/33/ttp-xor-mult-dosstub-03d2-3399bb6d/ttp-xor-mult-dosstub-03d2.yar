rule TTP_XOR_MULT_DOSStub_03d2 {
  strings:
    $key_03d2 = { 57 ba [2] 23 a2 [2] 64 a0 [2] 23 b1 [2] 6d bd [2] 61 b7 [2] 76 bc [2] 6d f2 [2] 50 }

  condition:
    any of them
}