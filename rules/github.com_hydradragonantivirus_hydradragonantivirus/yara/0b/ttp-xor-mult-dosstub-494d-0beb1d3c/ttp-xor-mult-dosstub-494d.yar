rule TTP_XOR_MULT_DOSStub_494d {
  strings:
    $key_494d = { 1d 25 [2] 69 3d [2] 2e 3f [2] 69 2e [2] 27 22 [2] 2b 28 [2] 3c 23 [2] 27 6d [2] 1a }

  condition:
    any of them
}