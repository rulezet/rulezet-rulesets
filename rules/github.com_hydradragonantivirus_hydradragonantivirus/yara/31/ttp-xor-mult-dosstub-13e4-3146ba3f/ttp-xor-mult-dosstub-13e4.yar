rule TTP_XOR_MULT_DOSStub_13e4 {
  strings:
    $key_13e4 = { 47 8c [2] 33 94 [2] 74 96 [2] 33 87 [2] 7d 8b [2] 71 81 [2] 66 8a [2] 7d c4 [2] 40 }

  condition:
    any of them
}