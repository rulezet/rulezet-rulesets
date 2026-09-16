rule TTP_XOR_MULT_DOSStub_3a5d {
  strings:
    $key_3a5d = { 6e 35 [2] 1a 2d [2] 5d 2f [2] 1a 3e [2] 54 32 [2] 58 38 [2] 4f 33 [2] 54 7d [2] 69 }

  condition:
    any of them
}