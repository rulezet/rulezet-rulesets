rule TTP_XOR_MULT_DOSStub_64e4 {
  strings:
    $key_64e4 = { 30 8c [2] 44 94 [2] 03 96 [2] 44 87 [2] 0a 8b [2] 06 81 [2] 11 8a [2] 0a c4 [2] 37 }

  condition:
    any of them
}