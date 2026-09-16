rule TTP_XOR_MULT_DOSStub_3345 {
  strings:
    $key_3345 = { 67 2d [2] 13 35 [2] 54 37 [2] 13 26 [2] 5d 2a [2] 51 20 [2] 46 2b [2] 5d 65 [2] 60 }

  condition:
    any of them
}