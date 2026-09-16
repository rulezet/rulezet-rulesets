rule TTP_XOR_MULT_DOSStub_5853 {
  strings:
    $key_5853 = { 0c 3b [2] 78 23 [2] 3f 21 [2] 78 30 [2] 36 3c [2] 3a 36 [2] 2d 3d [2] 36 73 [2] 0b }

  condition:
    any of them
}