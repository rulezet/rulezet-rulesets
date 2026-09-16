rule TTP_XOR_MULT_DOSStub_1355 {
  strings:
    $key_1355 = { 47 3d [2] 33 25 [2] 74 27 [2] 33 36 [2] 7d 3a [2] 71 30 [2] 66 3b [2] 7d 75 [2] 40 }

  condition:
    any of them
}