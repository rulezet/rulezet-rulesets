rule TTP_XOR_MULT_DOSStub_2a55 {
  strings:
    $key_2a55 = { 7e 3d [2] 0a 25 [2] 4d 27 [2] 0a 36 [2] 44 3a [2] 48 30 [2] 5f 3b [2] 44 75 [2] 79 }

  condition:
    any of them
}