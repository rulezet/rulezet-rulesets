rule TTP_XOR_MULT_DOSStub_5655 {
  strings:
    $key_5655 = { 02 3d [2] 76 25 [2] 31 27 [2] 76 36 [2] 38 3a [2] 34 30 [2] 23 3b [2] 38 75 [2] 05 }

  condition:
    any of them
}