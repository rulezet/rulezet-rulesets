rule TTP_XOR_MULT_DOSStub_1d4d {
  strings:
    $key_1d4d = { 49 25 [2] 3d 3d [2] 7a 3f [2] 3d 2e [2] 73 22 [2] 7f 28 [2] 68 23 [2] 73 6d [2] 4e }

  condition:
    any of them
}