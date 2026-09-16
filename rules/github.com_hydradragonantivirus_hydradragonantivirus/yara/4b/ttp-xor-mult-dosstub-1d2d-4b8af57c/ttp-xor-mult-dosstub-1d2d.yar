rule TTP_XOR_MULT_DOSStub_1d2d {
  strings:
    $key_1d2d = { 49 45 [2] 3d 5d [2] 7a 5f [2] 3d 4e [2] 73 42 [2] 7f 48 [2] 68 43 [2] 73 0d [2] 4e }

  condition:
    any of them
}