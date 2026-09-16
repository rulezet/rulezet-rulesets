rule TTP_XOR_MULT_DOSStub_c055 {
  strings:
    $key_c055 = { 94 3d [2] e0 25 [2] a7 27 [2] e0 36 [2] ae 3a [2] a2 30 [2] b5 3b [2] ae 75 [2] 93 }

  condition:
    any of them
}