rule TTP_XOR_MULT_DOSStub_22d9 {
  strings:
    $key_22d9 = { 76 b1 [2] 02 a9 [2] 45 ab [2] 02 ba [2] 4c b6 [2] 40 bc [2] 57 b7 [2] 4c f9 [2] 71 }

  condition:
    any of them
}