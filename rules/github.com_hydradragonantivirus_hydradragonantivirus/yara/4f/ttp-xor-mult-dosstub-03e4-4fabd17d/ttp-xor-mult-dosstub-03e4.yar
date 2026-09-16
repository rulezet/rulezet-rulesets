rule TTP_XOR_MULT_DOSStub_03e4 {
  strings:
    $key_03e4 = { 57 8c [2] 23 94 [2] 64 96 [2] 23 87 [2] 6d 8b [2] 61 81 [2] 76 8a [2] 6d c4 [2] 50 }

  condition:
    any of them
}