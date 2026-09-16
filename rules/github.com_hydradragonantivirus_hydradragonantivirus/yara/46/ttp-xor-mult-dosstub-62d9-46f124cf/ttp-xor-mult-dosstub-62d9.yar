rule TTP_XOR_MULT_DOSStub_62d9 {
  strings:
    $key_62d9 = { 36 b1 [2] 42 a9 [2] 05 ab [2] 42 ba [2] 0c b6 [2] 00 bc [2] 17 b7 [2] 0c f9 [2] 31 }

  condition:
    any of them
}