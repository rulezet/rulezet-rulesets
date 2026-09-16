rule TTP_XOR_MULT_DOSStub_734d {
  strings:
    $key_734d = { 27 25 [2] 53 3d [2] 14 3f [2] 53 2e [2] 1d 22 [2] 11 28 [2] 06 23 [2] 1d 6d [2] 20 }

  condition:
    any of them
}