rule TTP_XOR_MULT_DOSStub_0352 {
  strings:
    $key_0352 = { 57 3a [2] 23 22 [2] 64 20 [2] 23 31 [2] 6d 3d [2] 61 37 [2] 76 3c [2] 6d 72 [2] 50 }

  condition:
    any of them
}