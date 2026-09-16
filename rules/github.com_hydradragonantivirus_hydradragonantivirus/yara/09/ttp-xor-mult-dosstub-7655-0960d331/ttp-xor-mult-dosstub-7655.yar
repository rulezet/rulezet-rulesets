rule TTP_XOR_MULT_DOSStub_7655 {
  strings:
    $key_7655 = { 22 3d [2] 56 25 [2] 11 27 [2] 56 36 [2] 18 3a [2] 14 30 [2] 03 3b [2] 18 75 [2] 25 }

  condition:
    any of them
}