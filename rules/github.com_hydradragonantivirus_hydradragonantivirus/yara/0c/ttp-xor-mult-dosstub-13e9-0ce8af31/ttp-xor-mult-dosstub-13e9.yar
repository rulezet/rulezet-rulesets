rule TTP_XOR_MULT_DOSStub_13e9 {
  strings:
    $key_13e9 = { 47 81 [2] 33 99 [2] 74 9b [2] 33 8a [2] 7d 86 [2] 71 8c [2] 66 87 [2] 7d c9 [2] 40 }

  condition:
    any of them
}