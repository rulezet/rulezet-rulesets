rule TTP_XOR_MULT_DOSStub_70d2 {
  strings:
    $key_70d2 = { 24 ba [2] 50 a2 [2] 17 a0 [2] 50 b1 [2] 1e bd [2] 12 b7 [2] 05 bc [2] 1e f2 [2] 23 }

  condition:
    any of them
}