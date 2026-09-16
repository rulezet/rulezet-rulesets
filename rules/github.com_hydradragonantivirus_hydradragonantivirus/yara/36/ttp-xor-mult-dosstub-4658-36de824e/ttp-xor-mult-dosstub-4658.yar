rule TTP_XOR_MULT_DOSStub_4658 {
  strings:
    $key_4658 = { 12 30 [2] 66 28 [2] 21 2a [2] 66 3b [2] 28 37 [2] 24 3d [2] 33 36 [2] 28 78 [2] 15 }

  condition:
    any of them
}