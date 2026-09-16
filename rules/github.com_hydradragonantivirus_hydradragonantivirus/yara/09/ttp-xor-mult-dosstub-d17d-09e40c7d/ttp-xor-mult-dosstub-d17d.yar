rule TTP_XOR_MULT_DOSStub_d17d {
  strings:
    $key_d17d = { 85 15 [2] f1 0d [2] b6 0f [2] f1 1e [2] bf 12 [2] b3 18 [2] a4 13 [2] bf 5d [2] 82 }

  condition:
    any of them
}