rule TTP_XOR_MULT_DOSStub_2aca {
  strings:
    $key_2aca = { 7e a2 [2] 0a ba [2] 4d b8 [2] 0a a9 [2] 44 a5 [2] 48 af [2] 5f a4 [2] 44 ea [2] 79 }

  condition:
    any of them
}