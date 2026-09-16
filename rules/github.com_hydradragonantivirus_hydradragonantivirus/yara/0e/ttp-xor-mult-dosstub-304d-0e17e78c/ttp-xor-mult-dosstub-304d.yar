rule TTP_XOR_MULT_DOSStub_304d {
  strings:
    $key_304d = { 64 25 [2] 10 3d [2] 57 3f [2] 10 2e [2] 5e 22 [2] 52 28 [2] 45 23 [2] 5e 6d [2] 63 }

  condition:
    any of them
}