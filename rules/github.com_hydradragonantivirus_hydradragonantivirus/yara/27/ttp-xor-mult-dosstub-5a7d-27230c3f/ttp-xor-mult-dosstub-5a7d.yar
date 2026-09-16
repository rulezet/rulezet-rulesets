rule TTP_XOR_MULT_DOSStub_5a7d {
  strings:
    $key_5a7d = { 0e 15 [2] 7a 0d [2] 3d 0f [2] 7a 1e [2] 34 12 [2] 38 18 [2] 2f 13 [2] 34 5d [2] 09 }

  condition:
    any of them
}