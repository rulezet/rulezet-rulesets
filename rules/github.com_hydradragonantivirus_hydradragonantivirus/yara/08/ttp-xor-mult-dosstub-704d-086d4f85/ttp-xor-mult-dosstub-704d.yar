rule TTP_XOR_MULT_DOSStub_704d {
  strings:
    $key_704d = { 24 25 [2] 50 3d [2] 17 3f [2] 50 2e [2] 1e 22 [2] 12 28 [2] 05 23 [2] 1e 6d [2] 23 }

  condition:
    any of them
}