rule TTP_XOR_MULT_DOSStub_5158 {
  strings:
    $key_5158 = { 05 30 [2] 71 28 [2] 36 2a [2] 71 3b [2] 3f 37 [2] 33 3d [2] 24 36 [2] 3f 78 [2] 02 }

  condition:
    any of them
}