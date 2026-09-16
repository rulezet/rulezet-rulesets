rule TTP_XOR_MULT_DOSStub_3d1d {
  strings:
    $key_3d1d = { 69 75 [2] 1d 6d [2] 5a 6f [2] 1d 7e [2] 53 72 [2] 5f 78 [2] 48 73 [2] 53 3d [2] 6e }

  condition:
    any of them
}