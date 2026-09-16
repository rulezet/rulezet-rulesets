rule TTP_XOR_MULT_DOSStub_3a4e {
  strings:
    $key_3a4e = { 6e 26 [2] 1a 3e [2] 5d 3c [2] 1a 2d [2] 54 21 [2] 58 2b [2] 4f 20 [2] 54 6e [2] 69 }

  condition:
    any of them
}