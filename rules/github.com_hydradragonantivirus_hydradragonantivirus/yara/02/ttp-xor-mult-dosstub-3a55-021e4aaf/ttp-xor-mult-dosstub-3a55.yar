rule TTP_XOR_MULT_DOSStub_3a55 {
  strings:
    $key_3a55 = { 6e 3d [2] 1a 25 [2] 5d 27 [2] 1a 36 [2] 54 3a [2] 58 30 [2] 4f 3b [2] 54 75 [2] 69 }

  condition:
    any of them
}