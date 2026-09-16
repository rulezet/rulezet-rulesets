rule TTP_XOR_MULT_DOSStub_70d9 {
  strings:
    $key_70d9 = { 24 b1 [2] 50 a9 [2] 17 ab [2] 50 ba [2] 1e b6 [2] 12 bc [2] 05 b7 [2] 1e f9 [2] 23 }

  condition:
    any of them
}