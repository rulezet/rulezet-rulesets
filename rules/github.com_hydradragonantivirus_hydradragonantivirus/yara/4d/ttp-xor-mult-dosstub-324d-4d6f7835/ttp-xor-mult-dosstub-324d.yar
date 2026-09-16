rule TTP_XOR_MULT_DOSStub_324d {
  strings:
    $key_324d = { 66 25 [2] 12 3d [2] 55 3f [2] 12 2e [2] 5c 22 [2] 50 28 [2] 47 23 [2] 5c 6d [2] 61 }

  condition:
    any of them
}