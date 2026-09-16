rule TTP_XOR_MULT_DOSStub_03d4 {
  strings:
    $key_03d4 = { 57 bc [2] 23 a4 [2] 64 a6 [2] 23 b7 [2] 6d bb [2] 61 b1 [2] 76 ba [2] 6d f4 [2] 50 }

  condition:
    any of them
}