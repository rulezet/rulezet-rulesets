rule TTP_XOR_MULT_DOSStub_72d9 {
  strings:
    $key_72d9 = { 26 b1 [2] 52 a9 [2] 15 ab [2] 52 ba [2] 1c b6 [2] 10 bc [2] 07 b7 [2] 1c f9 [2] 21 }

  condition:
    any of them
}