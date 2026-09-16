rule TTP_XOR_MULT_DOSStub_1352 {
  strings:
    $key_1352 = { 47 3a [2] 33 22 [2] 74 20 [2] 33 31 [2] 7d 3d [2] 71 37 [2] 66 3c [2] 7d 72 [2] 40 }

  condition:
    any of them
}