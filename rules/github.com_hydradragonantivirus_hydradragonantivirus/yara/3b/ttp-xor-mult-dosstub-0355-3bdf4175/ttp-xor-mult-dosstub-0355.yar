rule TTP_XOR_MULT_DOSStub_0355 {
  strings:
    $key_0355 = { 57 3d [2] 23 25 [2] 64 27 [2] 23 36 [2] 6d 3a [2] 61 30 [2] 76 3b [2] 6d 75 [2] 50 }

  condition:
    any of them
}