rule TTP_XOR_MULT_DOSStub_4558 {
  strings:
    $key_4558 = { 11 30 [2] 65 28 [2] 22 2a [2] 65 3b [2] 2b 37 [2] 27 3d [2] 30 36 [2] 2b 78 [2] 16 }

  condition:
    any of them
}