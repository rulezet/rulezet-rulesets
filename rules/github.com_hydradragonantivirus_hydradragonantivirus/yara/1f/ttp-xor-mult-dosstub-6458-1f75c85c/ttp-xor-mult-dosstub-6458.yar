rule TTP_XOR_MULT_DOSStub_6458 {
  strings:
    $key_6458 = { 30 30 [2] 44 28 [2] 03 2a [2] 44 3b [2] 0a 37 [2] 06 3d [2] 11 36 [2] 0a 78 [2] 37 }

  condition:
    any of them
}