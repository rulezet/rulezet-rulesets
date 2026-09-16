rule TTP_XOR_MULT_DOSStub_764d {
  strings:
    $key_764d = { 22 25 [2] 56 3d [2] 11 3f [2] 56 2e [2] 18 22 [2] 14 28 [2] 03 23 [2] 18 6d [2] 25 }

  condition:
    any of them
}