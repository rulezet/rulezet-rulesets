rule TTP_XOR_MULT_DOSStub_41d9 {
  strings:
    $key_41d9 = { 15 b1 [2] 61 a9 [2] 26 ab [2] 61 ba [2] 2f b6 [2] 23 bc [2] 34 b7 [2] 2f f9 [2] 12 }

  condition:
    any of them
}