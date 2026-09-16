rule TTP_XOR_MULT_DOSStub_71e9 {
  strings:
    $key_71e9 = { 25 81 [2] 51 99 [2] 16 9b [2] 51 8a [2] 1f 86 [2] 13 8c [2] 04 87 [2] 1f c9 [2] 22 }

  condition:
    any of them
}