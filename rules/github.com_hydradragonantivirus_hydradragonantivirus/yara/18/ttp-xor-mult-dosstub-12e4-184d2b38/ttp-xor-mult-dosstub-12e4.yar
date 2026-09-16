rule TTP_XOR_MULT_DOSStub_12e4 {
  strings:
    $key_12e4 = { 46 8c [2] 32 94 [2] 75 96 [2] 32 87 [2] 7c 8b [2] 70 81 [2] 67 8a [2] 7c c4 [2] 41 }

  condition:
    any of them
}