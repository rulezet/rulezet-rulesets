rule TTP_XOR_MULT_DOSStub_744d {
  strings:
    $key_744d = { 20 25 [2] 54 3d [2] 13 3f [2] 54 2e [2] 1a 22 [2] 16 28 [2] 01 23 [2] 1a 6d [2] 27 }

  condition:
    any of them
}