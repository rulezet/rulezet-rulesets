rule TTP_XOR_MULT_DOSStub_17d8 {
  strings:
    $key_17d8 = { 43 b0 [2] 37 a8 [2] 70 aa [2] 37 bb [2] 79 b7 [2] 75 bd [2] 62 b6 [2] 79 f8 [2] 44 }

  condition:
    any of them
}