rule TTP_XOR_MULT_DOSStub_03d9 {
  strings:
    $key_03d9 = { 57 b1 [2] 23 a9 [2] 64 ab [2] 23 ba [2] 6d b6 [2] 61 bc [2] 76 b7 [2] 6d f9 [2] 50 }

  condition:
    any of them
}