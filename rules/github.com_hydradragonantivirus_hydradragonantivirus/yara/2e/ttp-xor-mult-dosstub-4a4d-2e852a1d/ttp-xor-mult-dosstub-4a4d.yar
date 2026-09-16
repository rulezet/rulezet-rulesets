rule TTP_XOR_MULT_DOSStub_4a4d {
  strings:
    $key_4a4d = { 1e 25 [2] 6a 3d [2] 2d 3f [2] 6a 2e [2] 24 22 [2] 28 28 [2] 3f 23 [2] 24 6d [2] 19 }

  condition:
    any of them
}