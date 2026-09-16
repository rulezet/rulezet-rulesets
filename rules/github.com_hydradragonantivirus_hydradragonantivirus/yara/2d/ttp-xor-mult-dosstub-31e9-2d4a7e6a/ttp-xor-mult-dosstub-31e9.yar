rule TTP_XOR_MULT_DOSStub_31e9 {
  strings:
    $key_31e9 = { 65 81 [2] 11 99 [2] 56 9b [2] 11 8a [2] 5f 86 [2] 53 8c [2] 44 87 [2] 5f c9 [2] 62 }

  condition:
    any of them
}