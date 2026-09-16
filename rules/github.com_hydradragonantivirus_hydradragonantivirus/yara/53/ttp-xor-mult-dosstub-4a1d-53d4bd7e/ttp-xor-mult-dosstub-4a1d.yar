rule TTP_XOR_MULT_DOSStub_4a1d {
  strings:
    $key_4a1d = { 1e 75 [2] 6a 6d [2] 2d 6f [2] 6a 7e [2] 24 72 [2] 28 78 [2] 3f 73 [2] 24 3d [2] 19 }

  condition:
    any of them
}