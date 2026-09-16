rule TTP_XOR_MULT_DOSStub_08e4 {
  strings:
    $key_08e4 = { 5c 8c [2] 28 94 [2] 6f 96 [2] 28 87 [2] 66 8b [2] 6a 81 [2] 7d 8a [2] 66 c4 [2] 5b }

  condition:
    any of them
}