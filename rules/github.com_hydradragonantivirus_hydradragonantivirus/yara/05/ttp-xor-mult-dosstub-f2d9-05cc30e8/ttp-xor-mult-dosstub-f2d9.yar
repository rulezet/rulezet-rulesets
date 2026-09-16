rule TTP_XOR_MULT_DOSStub_f2d9 {
  strings:
    $key_f2d9 = { a6 b1 [2] d2 a9 [2] 95 ab [2] d2 ba [2] 9c b6 [2] 90 bc [2] 87 b7 [2] 9c f9 [2] a1 }

  condition:
    any of them
}