rule TTP_XOR_MULT_DOSStub_3d4d {
  strings:
    $key_3d4d = { 69 25 [2] 1d 3d [2] 5a 3f [2] 1d 2e [2] 53 22 [2] 5f 28 [2] 48 23 [2] 53 6d [2] 6e }

  condition:
    any of them
}