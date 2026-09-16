rule TTP_XOR_MULT_DOSStub_79b1 {
  strings:
    $key_79b1 = { 2d d9 [2] 59 c1 [2] 1e c3 [2] 59 d2 [2] 17 de [2] 1b d4 [2] 0c df [2] 17 91 [2] 2a }

  condition:
    any of them
}