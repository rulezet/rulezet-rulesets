rule TTP_XOR_MULT_DOSStub_1ee9 {
  strings:
    $key_1ee9 = { 4a 81 [2] 3e 99 [2] 79 9b [2] 3e 8a [2] 70 86 [2] 7c 8c [2] 6b 87 [2] 70 c9 [2] 4d }

  condition:
    any of them
}