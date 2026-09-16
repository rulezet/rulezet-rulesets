rule TTP_XOR_MULT_DOSStub_41e9 {
  strings:
    $key_41e9 = { 15 81 [2] 61 99 [2] 26 9b [2] 61 8a [2] 2f 86 [2] 23 8c [2] 34 87 [2] 2f c9 [2] 12 }

  condition:
    any of them
}