rule TTP_XOR_MULT_DOSStub_3a58 {
  strings:
    $key_3a58 = { 6e 30 [2] 1a 28 [2] 5d 2a [2] 1a 3b [2] 54 37 [2] 58 3d [2] 4f 36 [2] 54 78 [2] 69 }

  condition:
    any of them
}