rule TTP_XOR_MULT_DOSStub_1758 {
  strings:
    $key_1758 = { 43 30 [2] 37 28 [2] 70 2a [2] 37 3b [2] 79 37 [2] 75 3d [2] 62 36 [2] 79 78 [2] 44 }

  condition:
    any of them
}