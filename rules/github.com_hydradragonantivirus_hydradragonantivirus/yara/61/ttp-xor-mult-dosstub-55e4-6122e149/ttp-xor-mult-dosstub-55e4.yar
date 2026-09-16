rule TTP_XOR_MULT_DOSStub_55e4 {
  strings:
    $key_55e4 = { 01 8c [2] 75 94 [2] 32 96 [2] 75 87 [2] 3b 8b [2] 37 81 [2] 20 8a [2] 3b c4 [2] 06 }

  condition:
    any of them
}