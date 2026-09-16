rule TTP_XOR_MULT_DOSStub_62e4 {
  strings:
    $key_62e4 = { 36 8c [2] 42 94 [2] 05 96 [2] 42 87 [2] 0c 8b [2] 00 81 [2] 17 8a [2] 0c c4 [2] 31 }

  condition:
    any of them
}