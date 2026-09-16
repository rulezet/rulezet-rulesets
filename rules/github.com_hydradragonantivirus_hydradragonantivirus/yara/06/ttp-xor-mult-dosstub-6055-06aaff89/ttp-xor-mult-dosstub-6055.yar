rule TTP_XOR_MULT_DOSStub_6055 {
  strings:
    $key_6055 = { 34 3d [2] 40 25 [2] 07 27 [2] 40 36 [2] 0e 3a [2] 02 30 [2] 15 3b [2] 0e 75 [2] 33 }

  condition:
    any of them
}