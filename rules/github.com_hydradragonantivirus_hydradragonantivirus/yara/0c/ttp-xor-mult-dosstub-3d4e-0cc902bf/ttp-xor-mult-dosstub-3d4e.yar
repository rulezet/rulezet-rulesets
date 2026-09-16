rule TTP_XOR_MULT_DOSStub_3d4e {
  strings:
    $key_3d4e = { 69 26 [2] 1d 3e [2] 5a 3c [2] 1d 2d [2] 53 21 [2] 5f 2b [2] 48 20 [2] 53 6e [2] 6e }

  condition:
    any of them
}