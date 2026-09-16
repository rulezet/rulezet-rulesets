rule TTP_XOR_MULT_DOSStub_2055 {
  strings:
    $key_2055 = { 74 3d [2] 00 25 [2] 47 27 [2] 00 36 [2] 4e 3a [2] 42 30 [2] 55 3b [2] 4e 75 [2] 73 }

  condition:
    any of them
}