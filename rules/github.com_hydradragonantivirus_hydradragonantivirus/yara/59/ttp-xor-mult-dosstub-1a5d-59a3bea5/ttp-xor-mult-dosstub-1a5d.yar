rule TTP_XOR_MULT_DOSStub_1a5d {
  strings:
    $key_1a5d = { 4e 35 [2] 3a 2d [2] 7d 2f [2] 3a 3e [2] 74 32 [2] 78 38 [2] 6f 33 [2] 74 7d [2] 49 }

  condition:
    any of them
}