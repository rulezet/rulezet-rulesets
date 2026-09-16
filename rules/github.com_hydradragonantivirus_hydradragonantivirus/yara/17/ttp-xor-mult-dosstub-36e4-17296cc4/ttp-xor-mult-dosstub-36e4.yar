rule TTP_XOR_MULT_DOSStub_36e4 {
  strings:
    $key_36e4 = { 62 8c [2] 16 94 [2] 51 96 [2] 16 87 [2] 58 8b [2] 54 81 [2] 43 8a [2] 58 c4 [2] 65 }

  condition:
    any of them
}