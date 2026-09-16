rule TTP_XOR_MULT_DOSStub_03e9 {
  strings:
    $key_03e9 = { 57 81 [2] 23 99 [2] 64 9b [2] 23 8a [2] 6d 86 [2] 61 8c [2] 76 87 [2] 6d c9 [2] 50 }

  condition:
    any of them
}