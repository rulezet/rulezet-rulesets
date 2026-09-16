rule TTP_XOR_MULT_DOSStub_7658 {
  strings:
    $key_7658 = { 22 30 [2] 56 28 [2] 11 2a [2] 56 3b [2] 18 37 [2] 14 3d [2] 03 36 [2] 18 78 [2] 25 }

  condition:
    any of them
}