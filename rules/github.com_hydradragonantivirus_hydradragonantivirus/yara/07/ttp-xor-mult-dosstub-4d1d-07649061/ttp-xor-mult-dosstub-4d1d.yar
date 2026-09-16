rule TTP_XOR_MULT_DOSStub_4d1d {
  strings:
    $key_4d1d = { 19 75 [2] 6d 6d [2] 2a 6f [2] 6d 7e [2] 23 72 [2] 2f 78 [2] 38 73 [2] 23 3d [2] 1e }

  condition:
    any of them
}