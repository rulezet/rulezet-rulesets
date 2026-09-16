rule TTP_XOR_MULT_DOSStub_5a58 {
  strings:
    $key_5a58 = { 0e 30 [2] 7a 28 [2] 3d 2a [2] 7a 3b [2] 34 37 [2] 38 3d [2] 2f 36 [2] 34 78 [2] 09 }

  condition:
    any of them
}