rule TTP_XOR_MULT_DOSStub_40d9 {
  strings:
    $key_40d9 = { 14 b1 [2] 60 a9 [2] 27 ab [2] 60 ba [2] 2e b6 [2] 22 bc [2] 35 b7 [2] 2e f9 [2] 13 }

  condition:
    any of them
}