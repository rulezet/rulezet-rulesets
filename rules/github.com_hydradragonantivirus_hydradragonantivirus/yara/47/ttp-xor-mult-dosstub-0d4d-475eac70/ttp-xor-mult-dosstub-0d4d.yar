rule TTP_XOR_MULT_DOSStub_0d4d {
  strings:
    $key_0d4d = { 59 25 [2] 2d 3d [2] 6a 3f [2] 2d 2e [2] 63 22 [2] 6f 28 [2] 78 23 [2] 63 6d [2] 5e }

  condition:
    any of them
}