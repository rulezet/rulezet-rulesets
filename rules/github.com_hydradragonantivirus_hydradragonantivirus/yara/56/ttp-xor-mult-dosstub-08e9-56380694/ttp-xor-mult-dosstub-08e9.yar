rule TTP_XOR_MULT_DOSStub_08e9 {
  strings:
    $key_08e9 = { 5c 81 [2] 28 99 [2] 6f 9b [2] 28 8a [2] 66 86 [2] 6a 8c [2] 7d 87 [2] 66 c9 [2] 5b }

  condition:
    any of them
}