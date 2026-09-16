rule TTP_XOR_MULT_DOSStub_5455 {
  strings:
    $key_5455 = { 00 3d [2] 74 25 [2] 33 27 [2] 74 36 [2] 3a 3a [2] 36 30 [2] 21 3b [2] 3a 75 [2] 07 }

  condition:
    any of them
}