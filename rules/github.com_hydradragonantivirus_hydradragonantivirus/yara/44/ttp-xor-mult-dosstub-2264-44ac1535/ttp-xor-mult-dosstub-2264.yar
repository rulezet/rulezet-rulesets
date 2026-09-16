rule TTP_XOR_MULT_DOSStub_2264 {
  strings:
    $key_2264 = { 76 0c [2] 02 14 [2] 45 16 [2] 02 07 [2] 4c 0b [2] 40 01 [2] 57 0a [2] 4c 44 [2] 71 }

  condition:
    any of them
}