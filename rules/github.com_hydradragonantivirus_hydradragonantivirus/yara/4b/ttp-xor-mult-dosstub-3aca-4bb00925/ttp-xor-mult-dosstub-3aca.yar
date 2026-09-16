rule TTP_XOR_MULT_DOSStub_3aca {
  strings:
    $key_3aca = { 6e a2 [2] 1a ba [2] 5d b8 [2] 1a a9 [2] 54 a5 [2] 58 af [2] 4f a4 [2] 54 ea [2] 69 }

  condition:
    any of them
}