rule TTP_XOR_MULT_DOSStub_07d2 {
  strings:
    $key_07d2 = { 53 ba [2] 27 a2 [2] 60 a0 [2] 27 b1 [2] 69 bd [2] 65 b7 [2] 72 bc [2] 69 f2 [2] 54 }

  condition:
    any of them
}