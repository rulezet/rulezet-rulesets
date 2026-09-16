rule TTP_XOR_MULT_DOSStub_04d9 {
  strings:
    $key_04d9 = { 50 b1 [2] 24 a9 [2] 63 ab [2] 24 ba [2] 6a b6 [2] 66 bc [2] 71 b7 [2] 6a f9 [2] 57 }

  condition:
    any of them
}