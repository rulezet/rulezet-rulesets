rule TTP_XOR_MULT_DOSStub_514d {
  strings:
    $key_514d = { 05 25 [2] 71 3d [2] 36 3f [2] 71 2e [2] 3f 22 [2] 33 28 [2] 24 23 [2] 3f 6d [2] 02 }

  condition:
    any of them
}