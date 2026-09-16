rule TTP_XOR_MULT_DOSStub_5352 {
  strings:
    $key_5352 = { 07 3a [2] 73 22 [2] 34 20 [2] 73 31 [2] 3d 3d [2] 31 37 [2] 26 3c [2] 3d 72 [2] 00 }

  condition:
    any of them
}