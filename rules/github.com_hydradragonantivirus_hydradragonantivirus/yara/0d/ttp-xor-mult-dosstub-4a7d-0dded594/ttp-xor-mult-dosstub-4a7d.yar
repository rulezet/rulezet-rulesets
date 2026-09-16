rule TTP_XOR_MULT_DOSStub_4a7d {
  strings:
    $key_4a7d = { 1e 15 [2] 6a 0d [2] 2d 0f [2] 6a 1e [2] 24 12 [2] 28 18 [2] 3f 13 [2] 24 5d [2] 19 }

  condition:
    any of them
}