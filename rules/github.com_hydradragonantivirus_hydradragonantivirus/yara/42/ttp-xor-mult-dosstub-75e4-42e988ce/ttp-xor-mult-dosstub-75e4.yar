rule TTP_XOR_MULT_DOSStub_75e4 {
  strings:
    $key_75e4 = { 21 8c [2] 55 94 [2] 12 96 [2] 55 87 [2] 1b 8b [2] 17 81 [2] 00 8a [2] 1b c4 [2] 26 }

  condition:
    any of them
}