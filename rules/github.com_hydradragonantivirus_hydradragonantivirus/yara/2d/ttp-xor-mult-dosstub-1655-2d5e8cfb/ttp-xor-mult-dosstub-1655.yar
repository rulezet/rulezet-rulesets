rule TTP_XOR_MULT_DOSStub_1655 {
  strings:
    $key_1655 = { 42 3d [2] 36 25 [2] 71 27 [2] 36 36 [2] 78 3a [2] 74 30 [2] 63 3b [2] 78 75 [2] 45 }

  condition:
    any of them
}