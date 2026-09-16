rule TTP_XOR_MULT_DOSStub_31d2 {
  strings:
    $key_31d2 = { 65 ba [2] 11 a2 [2] 56 a0 [2] 11 b1 [2] 5f bd [2] 53 b7 [2] 44 bc [2] 5f f2 [2] 62 }

  condition:
    any of them
}