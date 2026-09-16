rule TTP_XOR_MULT_DOSStub_524d {
  strings:
    $key_524d = { 06 25 [2] 72 3d [2] 35 3f [2] 72 2e [2] 3c 22 [2] 30 28 [2] 27 23 [2] 3c 6d [2] 01 }

  condition:
    any of them
}