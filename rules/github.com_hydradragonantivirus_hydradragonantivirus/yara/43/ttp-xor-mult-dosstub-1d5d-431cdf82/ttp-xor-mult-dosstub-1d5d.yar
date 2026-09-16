rule TTP_XOR_MULT_DOSStub_1d5d {
  strings:
    $key_1d5d = { 49 35 [2] 3d 2d [2] 7a 2f [2] 3d 3e [2] 73 32 [2] 7f 38 [2] 68 33 [2] 73 7d [2] 4e }

  condition:
    any of them
}