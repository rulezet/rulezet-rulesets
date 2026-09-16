rule TTP_XOR_MULT_DOSStub_1ae9 {
  strings:
    $key_1ae9 = { 4e 81 [2] 3a 99 [2] 7d 9b [2] 3a 8a [2] 74 86 [2] 78 8c [2] 6f 87 [2] 74 c9 [2] 49 }

  condition:
    any of them
}