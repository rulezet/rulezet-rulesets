rule TTP_XOR_MULT_DOSStub_17d6 {
  strings:
    $key_17d6 = { 43 be [2] 37 a6 [2] 70 a4 [2] 37 b5 [2] 79 b9 [2] 75 b3 [2] 62 b8 [2] 79 f6 [2] 44 }

  condition:
    any of them
}