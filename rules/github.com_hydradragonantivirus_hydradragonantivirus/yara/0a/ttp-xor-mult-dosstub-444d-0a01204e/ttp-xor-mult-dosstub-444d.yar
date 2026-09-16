rule TTP_XOR_MULT_DOSStub_444d {
  strings:
    $key_444d = { 10 25 [2] 64 3d [2] 23 3f [2] 64 2e [2] 2a 22 [2] 26 28 [2] 31 23 [2] 2a 6d [2] 17 }

  condition:
    any of them
}