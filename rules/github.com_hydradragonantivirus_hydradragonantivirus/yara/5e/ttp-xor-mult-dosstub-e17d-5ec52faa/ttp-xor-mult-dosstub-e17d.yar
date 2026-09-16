rule TTP_XOR_MULT_DOSStub_e17d {
  strings:
    $key_e17d = { b5 15 [2] c1 0d [2] 86 0f [2] c1 1e [2] 8f 12 [2] 83 18 [2] 94 13 [2] 8f 5d [2] b2 }

  condition:
    any of them
}