rule TTP_XOR_MULT_DOSStub_4755 {
  strings:
    $key_4755 = { 13 3d [2] 67 25 [2] 20 27 [2] 67 36 [2] 29 3a [2] 25 30 [2] 32 3b [2] 29 75 [2] 14 }

  condition:
    any of them
}