rule TTP_XOR_MULT_DOSStub_2209 {
  strings:
    $key_2209 = { 76 61 [2] 02 79 [2] 45 7b [2] 02 6a [2] 4c 66 [2] 40 6c [2] 57 67 [2] 4c 29 [2] 71 }

  condition:
    any of them
}