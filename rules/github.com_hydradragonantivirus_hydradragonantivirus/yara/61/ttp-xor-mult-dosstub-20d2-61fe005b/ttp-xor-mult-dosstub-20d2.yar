rule TTP_XOR_MULT_DOSStub_20d2 {
  strings:
    $key_20d2 = { 74 ba [2] 00 a2 [2] 47 a0 [2] 00 b1 [2] 4e bd [2] 42 b7 [2] 55 bc [2] 4e f2 [2] 73 }

  condition:
    any of them
}