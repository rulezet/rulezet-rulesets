rule TTP_XOR_MULT_DOSStub_6758 {
  strings:
    $key_6758 = { 33 30 [2] 47 28 [2] 00 2a [2] 47 3b [2] 09 37 [2] 05 3d [2] 12 36 [2] 09 78 [2] 34 }

  condition:
    any of them
}