rule TTP_XOR_MULT_DOSStub_49b1 {
  strings:
    $key_49b1 = { 1d d9 [2] 69 c1 [2] 2e c3 [2] 69 d2 [2] 27 de [2] 2b d4 [2] 3c df [2] 27 91 [2] 1a }

  condition:
    any of them
}