rule TTP_XOR_MULT_DOSStub_7358 {
  strings:
    $key_7358 = { 27 30 [2] 53 28 [2] 14 2a [2] 53 3b [2] 1d 37 [2] 11 3d [2] 06 36 [2] 1d 78 [2] 20 }

  condition:
    any of them
}