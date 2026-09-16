rule TTP_XOR_MULT_DOSStub_04d2 {
  strings:
    $key_04d2 = { 50 ba [2] 24 a2 [2] 63 a0 [2] 24 b1 [2] 6a bd [2] 66 b7 [2] 71 bc [2] 6a f2 [2] 57 }

  condition:
    any of them
}