rule TTP_XOR_MULT_DOSStub_41d2 {
  strings:
    $key_41d2 = { 15 ba [2] 61 a2 [2] 26 a0 [2] 61 b1 [2] 2f bd [2] 23 b7 [2] 34 bc [2] 2f f2 [2] 12 }

  condition:
    any of them
}