rule TTP_XOR_MULT_DOSStub_084d {
  strings:
    $key_084d = { 5c 25 [2] 28 3d [2] 6f 3f [2] 28 2e [2] 66 22 [2] 6a 28 [2] 7d 23 [2] 66 6d [2] 5b }

  condition:
    any of them
}