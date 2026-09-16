rule TTP_XOR_MULT_DOSStub_1d4e {
  strings:
    $key_1d4e = { 49 26 [2] 3d 3e [2] 7a 3c [2] 3d 2d [2] 73 21 [2] 7f 2b [2] 68 20 [2] 73 6e [2] 4e }

  condition:
    any of them
}