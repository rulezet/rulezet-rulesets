rule TTP_XOR_MULT_DOSStub_5154 {
  strings:
    $key_5154 = { 05 3c [2] 71 24 [2] 36 26 [2] 71 37 [2] 3f 3b [2] 33 31 [2] 24 3a [2] 3f 74 [2] 02 }

  condition:
    any of them
}