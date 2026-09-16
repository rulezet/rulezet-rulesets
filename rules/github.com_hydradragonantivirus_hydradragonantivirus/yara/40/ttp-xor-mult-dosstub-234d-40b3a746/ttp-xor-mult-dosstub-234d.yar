rule TTP_XOR_MULT_DOSStub_234d {
  strings:
    $key_234d = { 77 25 [2] 03 3d [2] 44 3f [2] 03 2e [2] 4d 22 [2] 41 28 [2] 56 23 [2] 4d 6d [2] 70 }

  condition:
    any of them
}