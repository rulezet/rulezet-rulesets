rule TTP_XOR_MULT_DOSStub_3a7d {
  strings:
    $key_3a7d = { 6e 15 [2] 1a 0d [2] 5d 0f [2] 1a 1e [2] 54 12 [2] 58 18 [2] 4f 13 [2] 54 5d [2] 69 }

  condition:
    any of them
}