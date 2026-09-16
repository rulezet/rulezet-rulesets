rule TTP_XOR_MULT_DOSStub_12e9 {
  strings:
    $key_12e9 = { 46 81 [2] 32 99 [2] 75 9b [2] 32 8a [2] 7c 86 [2] 70 8c [2] 67 87 [2] 7c c9 [2] 41 }

  condition:
    any of them
}