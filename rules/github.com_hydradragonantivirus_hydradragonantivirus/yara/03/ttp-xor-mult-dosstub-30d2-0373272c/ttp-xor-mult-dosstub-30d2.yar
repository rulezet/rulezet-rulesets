rule TTP_XOR_MULT_DOSStub_30d2 {
  strings:
    $key_30d2 = { 64 ba [2] 10 a2 [2] 57 a0 [2] 10 b1 [2] 5e bd [2] 52 b7 [2] 45 bc [2] 5e f2 [2] 63 }

  condition:
    any of them
}