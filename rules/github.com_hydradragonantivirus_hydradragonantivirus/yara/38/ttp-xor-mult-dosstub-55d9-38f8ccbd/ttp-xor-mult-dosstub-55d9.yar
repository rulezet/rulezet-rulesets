rule TTP_XOR_MULT_DOSStub_55d9 {
  strings:
    $key_55d9 = { 01 b1 [2] 75 a9 [2] 32 ab [2] 75 ba [2] 3b b6 [2] 37 bc [2] 20 b7 [2] 3b f9 [2] 06 }

  condition:
    any of them
}