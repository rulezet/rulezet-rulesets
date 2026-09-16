rule TTP_XOR_MULT_DOSStub_10d2 {
  strings:
    $key_10d2 = { 44 ba [2] 30 a2 [2] 77 a0 [2] 30 b1 [2] 7e bd [2] 72 b7 [2] 65 bc [2] 7e f2 [2] 43 }

  condition:
    any of them
}