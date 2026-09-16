rule TTP_XOR_MULT_DOSStub_7aca {
  strings:
    $key_7aca = { 2e a2 [2] 5a ba [2] 1d b8 [2] 5a a9 [2] 14 a5 [2] 18 af [2] 0f a4 [2] 14 ea [2] 29 }

  condition:
    any of them
}