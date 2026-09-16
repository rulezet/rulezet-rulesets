rule TTP_XOR_MULT_DOSStub_50d9 {
  strings:
    $key_50d9 = { 04 b1 [2] 70 a9 [2] 37 ab [2] 70 ba [2] 3e b6 [2] 32 bc [2] 25 b7 [2] 3e f9 [2] 03 }

  condition:
    any of them
}