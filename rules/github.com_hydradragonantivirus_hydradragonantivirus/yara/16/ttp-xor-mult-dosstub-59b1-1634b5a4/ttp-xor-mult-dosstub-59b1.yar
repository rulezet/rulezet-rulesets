rule TTP_XOR_MULT_DOSStub_59b1 {
  strings:
    $key_59b1 = { 0d d9 [2] 79 c1 [2] 3e c3 [2] 79 d2 [2] 37 de [2] 3b d4 [2] 2c df [2] 37 91 [2] 0a }

  condition:
    any of them
}