rule TTP_XOR_MULT_DOSStub_2d4d {
  strings:
    $key_2d4d = { 79 25 [2] 0d 3d [2] 4a 3f [2] 0d 2e [2] 43 22 [2] 4f 28 [2] 58 23 [2] 43 6d [2] 7e }

  condition:
    any of them
}