rule TTP_XOR_MULT_DOSStub_60d9 {
  strings:
    $key_60d9 = { 34 b1 [2] 40 a9 [2] 07 ab [2] 40 ba [2] 0e b6 [2] 02 bc [2] 15 b7 [2] 0e f9 [2] 33 }

  condition:
    any of them
}