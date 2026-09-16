rule TTP_XOR_MULT_DOSStub_034d {
  strings:
    $key_034d = { 57 25 [2] 23 3d [2] 64 3f [2] 23 2e [2] 6d 22 [2] 61 28 [2] 76 23 [2] 6d 6d [2] 50 }

  condition:
    any of them
}