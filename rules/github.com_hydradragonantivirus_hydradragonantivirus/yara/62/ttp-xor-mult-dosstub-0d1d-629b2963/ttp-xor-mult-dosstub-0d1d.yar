rule TTP_XOR_MULT_DOSStub_0d1d {
  strings:
    $key_0d1d = { 59 75 [2] 2d 6d [2] 6a 6f [2] 2d 7e [2] 63 72 [2] 6f 78 [2] 78 73 [2] 63 3d [2] 5e }

  condition:
    any of them
}