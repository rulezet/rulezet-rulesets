rule TTP_XOR_MULT_DOSStub_17e9 {
  strings:
    $key_17e9 = { 43 81 [2] 37 99 [2] 70 9b [2] 37 8a [2] 79 86 [2] 75 8c [2] 62 87 [2] 79 c9 [2] 44 }

  condition:
    any of them
}