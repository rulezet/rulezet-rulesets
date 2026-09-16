rule TTP_XOR_MULT_DOSStub_564d {
  strings:
    $key_564d = { 02 25 [2] 76 3d [2] 31 3f [2] 76 2e [2] 38 22 [2] 34 28 [2] 23 23 [2] 38 6d [2] 05 }

  condition:
    any of them
}