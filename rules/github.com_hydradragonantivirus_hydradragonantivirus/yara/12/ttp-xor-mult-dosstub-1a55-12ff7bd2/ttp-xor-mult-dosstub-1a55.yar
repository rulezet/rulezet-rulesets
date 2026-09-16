rule TTP_XOR_MULT_DOSStub_1a55 {
  strings:
    $key_1a55 = { 4e 3d [2] 3a 25 [2] 7d 27 [2] 3a 36 [2] 74 3a [2] 78 30 [2] 6f 3b [2] 74 75 [2] 49 }

  condition:
    any of them
}