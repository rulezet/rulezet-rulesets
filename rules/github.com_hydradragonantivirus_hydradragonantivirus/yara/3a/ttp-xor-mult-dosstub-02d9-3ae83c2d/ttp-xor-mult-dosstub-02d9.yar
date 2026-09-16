rule TTP_XOR_MULT_DOSStub_02d9 {
  strings:
    $key_02d9 = { 56 b1 [2] 22 a9 [2] 65 ab [2] 22 ba [2] 6c b6 [2] 60 bc [2] 77 b7 [2] 6c f9 [2] 51 }

  condition:
    any of them
}