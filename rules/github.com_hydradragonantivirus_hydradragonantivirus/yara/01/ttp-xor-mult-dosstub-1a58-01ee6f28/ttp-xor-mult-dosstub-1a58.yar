rule TTP_XOR_MULT_DOSStub_1a58 {
  strings:
    $key_1a58 = { 4e 30 [2] 3a 28 [2] 7d 2a [2] 3a 3b [2] 74 37 [2] 78 3d [2] 6f 36 [2] 74 78 [2] 49 }

  condition:
    any of them
}