rule TTP_XOR_MULT_DOSStub_1be9 {
  strings:
    $key_1be9 = { 4f 81 [2] 3b 99 [2] 7c 9b [2] 3b 8a [2] 75 86 [2] 79 8c [2] 6e 87 [2] 75 c9 [2] 48 }

  condition:
    any of them
}