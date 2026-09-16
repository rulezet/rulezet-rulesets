rule TTP_XOR_MULT_DOSStub_20e4 {
  strings:
    $key_20e4 = { 74 8c [2] 00 94 [2] 47 96 [2] 00 87 [2] 4e 8b [2] 42 81 [2] 55 8a [2] 4e c4 [2] 73 }

  condition:
    any of them
}