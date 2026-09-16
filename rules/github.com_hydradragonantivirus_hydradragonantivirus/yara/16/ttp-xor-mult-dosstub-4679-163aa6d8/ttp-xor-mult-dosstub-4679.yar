rule TTP_XOR_MULT_DOSStub_4679 {
  strings:
    $key_4679 = { 12 11 [2] 66 09 [2] 21 0b [2] 66 1a [2] 28 16 [2] 24 1c [2] 33 17 [2] 28 59 [2] 15 }

  condition:
    any of them
}