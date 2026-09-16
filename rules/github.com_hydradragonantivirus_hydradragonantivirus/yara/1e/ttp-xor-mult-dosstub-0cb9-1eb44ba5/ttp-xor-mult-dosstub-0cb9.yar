rule TTP_XOR_MULT_DOSStub_0cb9 {
  strings:
    $key_0cb9 = { 58 d1 [2] 2c c9 [2] 6b cb [2] 2c da [2] 62 d6 [2] 6e dc [2] 79 d7 [2] 62 99 [2] 5f }

  condition:
    any of them
}