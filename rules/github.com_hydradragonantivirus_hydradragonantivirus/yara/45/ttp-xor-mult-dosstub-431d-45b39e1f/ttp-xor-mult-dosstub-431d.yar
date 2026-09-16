rule TTP_XOR_MULT_DOSStub_431d {
  strings:
    $key_431d = { 17 75 [2] 63 6d [2] 24 6f [2] 63 7e [2] 2d 72 [2] 21 78 [2] 36 73 [2] 2d 3d [2] 10 }

  condition:
    any of them
}