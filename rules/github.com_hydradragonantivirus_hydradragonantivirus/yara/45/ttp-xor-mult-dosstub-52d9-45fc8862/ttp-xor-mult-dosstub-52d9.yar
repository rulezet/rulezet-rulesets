rule TTP_XOR_MULT_DOSStub_52d9 {
  strings:
    $key_52d9 = { 06 b1 [2] 72 a9 [2] 35 ab [2] 72 ba [2] 3c b6 [2] 30 bc [2] 27 b7 [2] 3c f9 [2] 01 }

  condition:
    any of them
}