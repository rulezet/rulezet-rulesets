rule TTP_XOR_MULT_DOSStub_5a54 {
  strings:
    $key_5a54 = { 0e 3c [2] 7a 24 [2] 3d 26 [2] 7a 37 [2] 34 3b [2] 38 31 [2] 2f 3a [2] 34 74 [2] 09 }

  condition:
    any of them
}