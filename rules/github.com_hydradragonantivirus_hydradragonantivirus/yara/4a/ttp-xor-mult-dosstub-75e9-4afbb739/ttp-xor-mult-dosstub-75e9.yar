rule TTP_XOR_MULT_DOSStub_75e9 {
  strings:
    $key_75e9 = { 21 81 [2] 55 99 [2] 12 9b [2] 55 8a [2] 1b 86 [2] 17 8c [2] 00 87 [2] 1b c9 [2] 26 }

  condition:
    any of them
}