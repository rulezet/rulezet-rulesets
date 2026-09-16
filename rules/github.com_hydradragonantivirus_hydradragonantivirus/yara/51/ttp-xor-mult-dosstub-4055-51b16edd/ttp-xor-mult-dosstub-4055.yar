rule TTP_XOR_MULT_DOSStub_4055 {
  strings:
    $key_4055 = { 14 3d [2] 60 25 [2] 27 27 [2] 60 36 [2] 2e 3a [2] 22 30 [2] 35 3b [2] 2e 75 [2] 13 }

  condition:
    any of them
}