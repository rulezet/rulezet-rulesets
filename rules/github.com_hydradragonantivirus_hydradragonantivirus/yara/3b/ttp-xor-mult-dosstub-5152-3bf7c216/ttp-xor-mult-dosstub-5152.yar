rule TTP_XOR_MULT_DOSStub_5152 {
  strings:
    $key_5152 = { 05 3a [2] 71 22 [2] 36 20 [2] 71 31 [2] 3f 3d [2] 33 37 [2] 24 3c [2] 3f 72 [2] 02 }

  condition:
    any of them
}