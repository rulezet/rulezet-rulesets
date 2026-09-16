rule TTP_XOR_MULT_DOSStub_334d {
  strings:
    $key_334d = { 67 25 [2] 13 3d [2] 54 3f [2] 13 2e [2] 5d 22 [2] 51 28 [2] 46 23 [2] 5d 6d [2] 60 }

  condition:
    any of them
}