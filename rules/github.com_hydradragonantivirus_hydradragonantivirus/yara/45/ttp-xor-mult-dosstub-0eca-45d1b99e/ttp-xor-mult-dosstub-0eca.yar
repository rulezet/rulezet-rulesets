rule TTP_XOR_MULT_DOSStub_0eca {
  strings:
    $key_0eca = { 5a a2 [2] 2e ba [2] 69 b8 [2] 2e a9 [2] 60 a5 [2] 6c af [2] 7b a4 [2] 60 ea [2] 5d }

  condition:
    any of them
}