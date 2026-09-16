rule TTP_XOR_MULT_DOSStub_794d {
  strings:
    $key_794d = { 2d 25 [2] 59 3d [2] 1e 3f [2] 59 2e [2] 17 22 [2] 1b 28 [2] 0c 23 [2] 17 6d [2] 2a }

  condition:
    any of them
}