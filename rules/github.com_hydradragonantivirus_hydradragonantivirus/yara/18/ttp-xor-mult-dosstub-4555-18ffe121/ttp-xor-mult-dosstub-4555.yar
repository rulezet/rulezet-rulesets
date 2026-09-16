rule TTP_XOR_MULT_DOSStub_4555 {
  strings:
    $key_4555 = { 11 3d [2] 65 25 [2] 22 27 [2] 65 36 [2] 2b 3a [2] 27 30 [2] 30 3b [2] 2b 75 [2] 16 }

  condition:
    any of them
}