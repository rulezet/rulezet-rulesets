rule TTP_XOR_MULT_DOSStub_06e4 {
  strings:
    $key_06e4 = { 52 8c [2] 26 94 [2] 61 96 [2] 26 87 [2] 68 8b [2] 64 81 [2] 73 8a [2] 68 c4 [2] 55 }

  condition:
    any of them
}