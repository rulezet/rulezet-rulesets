rule TTP_XOR_MULT_DOSStub_4eca {
  strings:
    $key_4eca = { 1a a2 [2] 6e ba [2] 29 b8 [2] 6e a9 [2] 20 a5 [2] 2c af [2] 3b a4 [2] 20 ea [2] 1d }

  condition:
    any of them
}