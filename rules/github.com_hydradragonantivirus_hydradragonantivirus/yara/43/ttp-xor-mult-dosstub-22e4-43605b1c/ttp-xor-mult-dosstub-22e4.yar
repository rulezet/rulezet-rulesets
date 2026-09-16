rule TTP_XOR_MULT_DOSStub_22e4 {
  strings:
    $key_22e4 = { 76 8c [2] 02 94 [2] 45 96 [2] 02 87 [2] 4c 8b [2] 40 81 [2] 57 8a [2] 4c c4 [2] 71 }

  condition:
    any of them
}