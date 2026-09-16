rule TTP_XOR_MULT_DOSStub_71e4 {
  strings:
    $key_71e4 = { 25 8c [2] 51 94 [2] 16 96 [2] 51 87 [2] 1f 8b [2] 13 81 [2] 04 8a [2] 1f c4 [2] 22 }

  condition:
    any of them
}