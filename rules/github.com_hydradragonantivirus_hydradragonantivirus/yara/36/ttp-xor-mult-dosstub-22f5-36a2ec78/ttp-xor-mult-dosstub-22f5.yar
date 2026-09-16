rule TTP_XOR_MULT_DOSStub_22f5 {
  strings:
    $key_22f5 = { 76 9d [2] 02 85 [2] 45 87 [2] 02 96 [2] 4c 9a [2] 40 90 [2] 57 9b [2] 4c d5 [2] 71 }

  condition:
    any of them
}