rule TTP_XOR_MULT_DOSStub_3355 {
  strings:
    $key_3355 = { 67 3d [2] 13 25 [2] 54 27 [2] 13 36 [2] 5d 3a [2] 51 30 [2] 46 3b [2] 5d 75 [2] 60 }

  condition:
    any of them
}