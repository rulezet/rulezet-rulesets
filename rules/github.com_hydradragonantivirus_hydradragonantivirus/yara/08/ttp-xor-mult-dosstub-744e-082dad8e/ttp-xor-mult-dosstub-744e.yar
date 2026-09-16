rule TTP_XOR_MULT_DOSStub_744e {
  strings:
    $key_744e = { 20 26 [2] 54 3e [2] 13 3c [2] 54 2d [2] 1a 21 [2] 16 2b [2] 01 20 [2] 1a 6e [2] 27 }

  condition:
    any of them
}